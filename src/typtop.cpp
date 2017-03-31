//
// Created by Rahul Chatterjee on 3/28/17.
//

#include <assert.h>
#include "typtop.h"
using CryptoPP::FileSource;

// Password length for random entries
#define DEFAULT_PW_LENGTH 16

TypTop::TypTop(const string& _db_fname, const string& real_pw) : db_fname(_db_fname) {
#ifdef DEBUG
    std::srand(254);
#else
    std::srand( (unsinged)std::time(0) );
#endif
    if (!db.ParseFromIstream(new std::fstream(db_fname, ios::in|ios::binary))) {
        std::cerr << "Something went wrong or the file is empty" << endl;
        assert(!real_pw.empty());
        initialize(db_fname, real_pw);
    } else {
        pkobj.set_pk(db.ch().public_key());
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
        for(int i=0; i<W_size; i++)
            db.add_w();
    }
    string ctx;
    WaitlistEntry wlent;
    wlent.set_pw(typo); wlent.set_ts(ts);

    pkobj.pk_encrypt(wlent.SerializeAsString(), ctx);
    int32_t curr_index = db.h().indexj();
    db.set_w(curr_index, ctx);
    curr_index = (curr_index + 1) % W_size;
    db.mutable_h()->set_indexj(curr_index);
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
    this->real_pw = real_pw;
    // - Set config header
    ch->set_install_id(get_install_id());
    pkobj.initialize();
    ch->set_public_key(pkobj.serialize_pk());
    SecByteBlock global_salt(AES::BLOCKSIZE);
    PRNG.GenerateBlock(global_salt, global_salt.size());  // random element
    ch->set_global_salt((const char*)global_salt.data(), global_salt.size());

    string sk_str = pkobj.serialize_sk(), sk_ctx;

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
        pwencrypt(T_cache[i], sk_str, sk_ctx);
        _insert_into_typo_cache(i, sk_ctx, (i == 0 ? INT_MAX : T_size - i));
    }
    Header* h = db.mutable_h();
    h->set_indexj(PRNG.GenerateWord32(0, W_size-1)); // initialize the indexj to a random value
    assert(ench.freq_size() == T_size);
    string ench_ctx;
    pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
    h->set_enc_header(ench_ctx);

// For debugging
#ifdef DEBUG
    string ench_str;
    pkobj.pk_decrypt(ench_ctx, ench_str);
    assert (ench_str == ench.SerializeAsString());
    ench_str.clear();
    pkobj.pk_decrypt(h->enc_header(), ench_str);  // For debugging
    assert (ench_str == ench.SerializeAsString()); // For debugging
#endif

    fill_waitlist_w_garbage();   // sets W
    db.mutable_h()->set_sys_state(SystemStatus::ALL_GOOD);
    assert(db.IsInitialized());
#ifdef DEBUG
    cerr << "db initialized" << endl;
    if (db.t_size() != ench.freq_size() ||
            db.t_size() != ench.last_used_size() ||
            ench.last_used_size() != T_size) {
        cerr << __FILE__ << __LINE__ << " : "
             << " ---> db.t=" << db.t_size() << ", freq=" << ench.freq_size()
             << " last_used=" << ench.last_used_size() << " T-size=" << T_size << endl;
    }
#endif
}

void TypTop::insert_into_log(const string& pw, bool in_cache, int64_t ts) {
    assert(!real_pw.empty());
    Log* l = db.add_l();
    l->set_in_cache(in_cache);
    l->set_istop5fixable(top5fixable(real_pw, pw));
    l->set_edit_dist(min(edit_distance(pw, real_pw), 5));
    l->set_rel_entropy(-99);  // TODO: Find a way to estimate this
    SecByteBlock g_salt((const byte *)db.ch().global_salt().data(), db.ch().global_salt().size());
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
 * @return Whether or not the entered password is allowable.
 */
bool TypTop::check(const string &pw, bool were_right) {
    ench.Clear();
    string sk_str, enc_header_str;
    /* Standard book-keeping */
    db.mutable_h()->set_login_count(db.h().login_count()+1);

    // check the password
    int i = 0;
    for(i=0; i<T_size; i++) {
        sk_str.clear();
        if(pwdecrypt(pw, db.t(i), sk_str)) { // match found
            break;
        }
    }
    if (i ==0 && !were_right) { // old password entered
        // TODO: Deal with it
        db.mutable_h()->set_sys_state(SystemStatus::PW_CHANGED);
    }
    if (i == T_size) { // not found in the typo cache
        if(were_right) { // probably password changed, don't do anything this time just set the sys-status
            // db.mutable_h()->set_sys_state(SystemStatus::PW_CHANGED);
            this->initialize(this->db_fname, pw);
        } else {
            add_to_waitlist(pw, now());
        }
    } else { // match_found is true
        cerr << b64encode(sk_str) << endl;
        pkobj.set_sk(sk_str);
        pkobj.pk_decrypt(db.h().enc_header(), enc_header_str);
        ench.ParseFromString(enc_header_str);
        this->real_pw = ench.pw();
        if (i>0) {
            ench.set_freq(i, ench.freq(i)+1);
            ench.set_last_used(i, now());
        }
        process_waitlist(sk_str);
        permute_typo_cache(sk_str);

        cerr << ench.DebugString() << endl;
        assert(ench.IsInitialized());
        string ench_ctx, _t_ench_str;

        pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
        pkobj.pk_decrypt(ench_ctx, _t_ench_str);

        db.mutable_h()->set_enc_header(ench_ctx);
        cerr<<ench_ctx.length() << " " << ench_ctx.size() << endl
            << b64encode(ench_ctx) << endl;
        assert(_t_ench_str == ench.SerializeAsString());
        ench.Clear();
        were_right = true;
    }
    return were_right;
}

void TypTop::_insert_into_typo_cache(const int index, const string &sk_ctx,
                                     const int freq) {
    for(int i=ench.freq_size(); i<T_size; i++) { // assume all the three arrays (freq, last_used, T) are in sync
        ench.add_freq(-1);
        ench.add_last_used(-1);
        db.add_t();
    }

    db.set_t(index, sk_ctx);
    int64_t now_t = now();
    ench.set_freq(index, freq);
    ench.set_last_used(index, now_t);
}

void TypTop::add_to_typo_cache(const string &pw, const int freq,
                               const string &sk_str) {
    throw ("Not implemented!!");
}

/**
 * For security reason we should keep the typo cache permuted after
 * every time the cache is altered.
 */
void TypTop::permute_typo_cache(const string& sk_str) {
    vector<int> idx(T_size-1);
    iota(idx.begin(), idx.end(), 0);
    random_shuffle(idx.begin(), idx.end());
    auto random_perm = [idx](int i){return idx[i];};

    random_shuffle(db.mutable_t()->begin()+1, db.mutable_t()->end(), random_perm);
    random_shuffle(ench.mutable_freq()->begin()+1, ench.mutable_freq()->end(), random_perm);
    random_shuffle(ench.mutable_last_used()->begin()+1, ench.mutable_last_used()->end(), random_perm);
    int64_t t_now = now();
    string sk_ctx;
    for(int i=1; i<T_size; i++) { // don't remove real password
        if(t_now - ench.last_used(i) > db.ch().typo_expiry_time()){
            string fake_pw(DEFAULT_PW_LENGTH, 0);
            PRNG.GenerateBlock((byte*)fake_pw.data(), fake_pw.size());
            pwencrypt(fake_pw, sk_str, sk_ctx);
            _insert_into_typo_cache(i, sk_ctx, -1);
        }
    }
}

/**
 * 1. Decrypt the waitlist, add to log, and consolidate
 * 2. for each consolidated and validated entries
 *     try to insert in the typo cache
 * @param ench
 */
void TypTop::process_waitlist(const string& sk_str) {
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

    vector<int> freq_vec(ench.freq().begin(), ench.freq().end());
    auto freq_vec_sorted_idx = sort_indexes(freq_vec);
    for(auto e: wl_typo) {
        cerr<< e.first << " :: " << e.second << endl;
        string pw = e.first;
        int freq = e.second;
        string sk_ctx;
        for(auto i: freq_vec_sorted_idx) {
            // try to insert at i-th location
            if (win(ench.freq((int)i), freq)) {
                pwencrypt(pw, sk_str, sk_ctx);
                _insert_into_typo_cache((int) i, sk_ctx, max(freq, freq_vec[i] + 1));
                break;
            }
        }
        // add_to_typo_cache(e.first, e.second, sk_str, ench);
    }
    fill_waitlist_w_garbage();
}
