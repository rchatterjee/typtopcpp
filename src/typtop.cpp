//
// Created by Rahul Chatterjee on 3/28/17.
//

#include "typtop.h"
using CryptoPP::FileSource;
#include "pw_crypto.h"
#include "typo_util.hpp"

// Password length for random entries
#define DEFAULT_PW_LENGTH 16

TypTop::TypTop(const string& _db_fname, const string& real_pw) : db_fname(_db_fname) {
    if (!db.ParseFromIstream(new std::fstream(db_fname, ios::in|ios::binary))) {
        std::cerr << "Something went wrong or the file is empty" << endl;
        assert(!real_pw.empty());
        initialize(db_fname, real_pw);
    }
}

TypTop::~TypTop() {
    string db_bak = db_fname + ".bak";
    std::fstream of(db_bak, ios::out|ios::binary);
    db.SerializeToOstream(&of);
    rename(db_bak.c_str(), db_fname.c_str());
}


void TypTop::add_to_waitlist(const string& typo, int64_t ts) {
    if (db.w_size() < W_size) {
        db.mutable_w()->Reserve(W_size);
    }
    string ctx;
    WaitlistEntry wlent;
    wlent.set_pw(typo); wlent.set_ts(ts);

    pkobj.pk_encrypt(wlent.SerializeAsString(), ctx);

    int32_t curr_index = db.h().indexj();
    db.set_w(curr_index, ctx);
    curr_index = (curr_index + 1) % W_size;
    db.mutable_h()->set_indexj(curr_index+1);
}

void TypTop::fill_waitlist_w_garbage() {
    for(int i=0; i<W_size; i++) {
        string b(DEFAULT_PW_LENGTH, 0);
        PRNG.GenerateBlock((byte *)b.data(), b.size());
        add_to_waitlist(b, -1); // ts = -1 for garbage strings
    }
}

void TypTop::initialize(const string& _db_fname, const string& real_pw) {
    ConfigHeader* ch = db.mutable_ch();
    static EncHeaderData ench;  // encrypt before putting it inside header

    // - Set config header
    ch->set_install_id(get_install_id());
    pkobj.initialize();
    ch->set_public_key(pkobj.serialize_pk());
    SecByteBlock global_salt(AES::BLOCKSIZE);
    PRNG.GenerateBlock(global_salt, global_salt.size());  // random element
    ch->set_global_salt((const char*)global_salt.data(), global_salt.size());

    string sk_str = pkobj.serialize_sk();

    // --- Set the encryption header
    ench.set_pw(real_pw);
    std::vector<string>T_cache(T_size-1);
    get_typos(real_pw, T_cache);
    T_cache.insert(T_cache.begin(), real_pw);  // the real password is always at the 0-th location
    assert( T_cache.size() == T_size );
    for(int i=0; i<T_size; i++) {
        if (T_cache[i].empty()) { // generate random
            T_cache[i].resize(DEFAULT_PW_LENGTH, 0);
            PRNG.GenerateBlock((byte *)T_cache[i].data(), T_cache.size());
        } else {
            insert_into_log(T_cache[i], true, -1); // sets L
        }
        add_to_typo_cache(T_cache[i],
                          (i == 0 ? std::numeric_limits<int>::infinity() : T_size - i),
                          sk_str, ench);
    }
    Header* h = db.mutable_h();
    h->set_indexj(PRNG.GenerateWord32(0, W_size)); // initialize the indexj to a random value
    pkobj.pk_encrypt(ench.SerializeAsString(), *(h->mutable_enc_header()));

    fill_waitlist_w_garbage();   // sets W
    cout << "db: " << db.DebugString() << endl;
    assert(db.IsInitialized());
}

void TypTop::insert_into_log(const string& pw, bool in_cache, int64_t ts) {
    Log* l = db.add_l();
    l->set_in_cache(in_cache);
    l->set_istop5fixable(top5fixable(real_pw, pw));
    l->set_edit_dist(min(edit_distance(pw, real_pw), 5));
    l->set_rel_entropy(-99);  // TODO: Find a way toestimate this
    static SecByteBlock g_salt((const byte *)db.ch().global_salt().data(), db.ch().global_salt().size());
    l->set_tid(compute_id(g_salt, pw));
    l->set_ts(time(NULL));
    l->set_localtime(localtime());
}

/**
 * Checks the password in the TypTop cache.
 * 1. Check the pw against db.t()
 * 2. If match found, process waitlist.
 * 2a.
 * 3. If no match found add to waitlist
 * 3a.
 * @param pw: typed password (could be wrong)
 * @param were_right: The return from previous authentication mechanism, such as pam_unix.
 * @return Whether or not the enteredf password is allowable.
 */
bool TypTop::check(const string &pw, bool were_right) {
    string sk_str, enc_header_str;
    /* Standard book-keeping */
    db.mutable_h()->set_login_count(db.h().login_count()+1);

    // check the password
    int i = 0;
    for(i=0; i<T_size; i++) {
        if(pwdecrypt(pw, db.t(i), sk_str)) { // match found
            break;
        }
    }
    if (i == T_size) { // not found in the typo cache
        if(were_right) { // probably password changed, don't do anything this time just set the sys-status
            // db.mutable_h()->set_sys_state(SystemStatus::PW_CHANGED);
            this->initialize(this->db_fname, pw);
        } else {
            add_to_waitlist(pw, now());
        }
    } else { // match_found is true
        pkobj.set_sk(sk_str);
        // decrypt real_pw
        pkobj.pk_decrypt(db.h().enc_header(), enc_header_str);
        EncHeaderData ench;
        ench.ParseFromString(enc_header_str);
        this->real_pw = ench.pw();
        process_waitlist(sk_str, ench);
        if (i>0) {
            ench.set_freq(i, ench.freq(i)+1);
            ench.set_last_used(i, now());
        }
        permute_typo_cache(ench, sk_str);
        were_right = true;
        pkobj.pk_encrypt(ench.SerializeAsString(), *(db.mutable_h()->mutable_enc_header()));
    }
    return were_right;
}

/**
 * Compares the f_o (old f) and f_n (new f) to
 * decide whether or not the old should be evicted
 * Right now the probability of eviction is f_n/(f_n+f_o)
 */
bool win(int f_o, int f_n) {
    if(f_o < 0) return true; // the row had garbage
    int d = f_o + f_n;
    assert(d>0);
    return (PRNG.GenerateWord32(0, (uint32_t)d) < f_n);
}

void TypTop::insert_to_typo_cache(const int index, const string& sk_ctx,
                                  const int freq, EncHeaderData& ench) {
    db.set_t(index, sk_ctx);
    int64_t now_t = now();
    ench.set_freq(index, freq);
    ench.set_last_used(index, now_t);
}

void TypTop::add_to_typo_cache(const string &pw, const int freq,
                               const string &sk_str, EncHeaderData &ench) {
    string sk_ctx;
    if (ench.freq_size() < T_size) { // assume all the three arrays (freq, last_used, T) are in sync
        ench.mutable_freq()->Resize(T_size, -1);
        ench.mutable_last_used()->Resize(T_size, -1);
        db.mutable_t()->Reserve(T_size);
    }
    static vector<int> freq_vec_sorted_idx(ench.freq().begin(), ench.freq().end());
    for(auto i: freq_vec_sorted_idx) {
        // try to insert at i-th location
        if (win(ench.freq(i), freq)) {
            pwencrypt(pw, sk_str, sk_ctx);
            insert_to_typo_cache(i, sk_ctx, max(freq, freq_vec_sorted_idx[i]+1), ench);
        }
    }
}

/**
 * For security reason we should keep the typo cache permuted after
 * every time the cache is altered.
 */
void TypTop::permute_typo_cache(EncHeaderData& ench, const string& sk_str) {
    vector<int> idx(T_size-1);
    iota(idx.begin(), idx.end(), 0);
    random_shuffle(idx.begin(), idx.end());
    auto random_perm = [idx](int i){return idx[i];};

    random_shuffle(db.mutable_t()->begin()+1, db.mutable_t()->end(), random_perm);
    random_shuffle(ench.mutable_freq()->begin()+1, ench.mutable_freq()->end(), random_perm);
    random_shuffle(ench.mutable_last_used()->begin()+1, ench.mutable_last_used()->end(), random_perm);
    int64_t t_now = now();
    string sk_ctx;
    for(int i=0; i<T_size; i++) {
        if(t_now - ench.last_used(i) > db.ch().typo_expiry_time()){
            string fake_pw(DEFAULT_PW_LENGTH, 0);
            PRNG.GenerateBlock((byte*)fake_pw.data(), fake_pw.size());
            pwencrypt(fake_pw, sk_str, sk_ctx);
            insert_to_typo_cache(i, sk_ctx, -1, ench);
        }
    }
}

/**
 * 1. Decrypt the waitlist, add to log, and consolidate
 * 2. for each consolidated and validated entries
 *     try to insert in the typo cache
 * @param ench
 */
void TypTop::process_waitlist(const string& sk_str, EncHeaderData &ench) {
    assert (!this->real_pw.empty());
    map<string, int> wl_typo;
    WaitlistEntry wlent;
    for(int i=0; i<W_size; i++) {
        string wlent_str;
        pkobj.pk_decrypt(db.w(i), wlent_str);
        wlent.ParseFromString(wlent_str);
        if (wlent.ts()>0) // no points logging the garbage of the Wait-list
            insert_into_log(wlent.pw(), false, wlent.ts());
        if(meets_typo_policy(real_pw, wlent.pw())){
            wl_typo[wlent.pw()] = wl_typo[wlent.pw()] + 1; // stl map initialized to 0 by default!!
        }
    }
    for(auto e: wl_typo) {
        add_to_typo_cache(e.first, e.second, sk_str, ench);
    }
    fill_waitlist_w_garbage();
}
