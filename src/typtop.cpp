//
// Created by Rahul Chatterjee on 3/28/17.
//

#include <assert.h>
#include <random>
#include <dirent.h>
#include <libgen.h>
#include "typtop.h"

using CryptoPP::FileSource;

// Password length for random entries
#define DEFAULT_PW_LENGTH 16

#undef GOOGLE_LOG
pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;

TypTop::TypTop(const string &_db_fname) : db_fname(_db_fname) {
    setup_logger(plog::debug);
    LOG_INFO << " -- TypTop Begin -- ";
    google::protobuf::SetLogHandler(NULL);  // stop annoying protobuf error messages
    auto o_mask = umask(0117);
    fstream idbf(db_fname, ios::in | ios::binary);
    if(!idbf.good()) {
        LOG_WARNING << "TypTop db is not initialized: " << db.h().sys_state();
        db.mutable_ch()->set_install_id(get_install_id());
        return;
    }
    try {
        if(db.ParseFromIstream(&idbf)) {
            LOG_INFO << "TypTop initialized: " << bool(db.h().sys_state() == SystemStatus::ALL_GOOD);
            pkobj.set_pk(db.ch().public_key());
        } else {
            db.mutable_ch()->set_install_id(get_install_id());
            LOG_ERROR << "Could not parse the DB file.";
        }
    } catch (google::protobuf::FatalException ex) {
        db.mutable_h()->set_sys_state(SystemStatus::UNINITIALIZED);
        db.mutable_ch()->set_install_id(get_install_id());
        LOG_ERROR << "DB file is corrupted, will (re)initialize next time.";
    }
    umask(o_mask);
}

void TypTop::save() const {
    if (!is_initialized()) return; // no need to do anything
    // check if the directory exists
#ifdef WIN32
    throw("No idea what to do.")
#else
    const char* db_dirname = dirname(strdup(db_fname.c_str()));
    DIR* dir;
    if(!(dir = opendir(db_dirname))) {
        LOGD << "Trying to create directory " << db_dirname << ".\n";
        if(mkdir(db_dirname, 0775) != 0) // (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)))
            LOG_ERROR << strerror(errno) << " " << getuid() << endl;
    } else {
        LOG_DEBUG << "Directory '" << db_dirname << "' exists.";
    }
    closedir(dir);
    /* Each time this function gets called, the counter is incremented by the calling thread.*/
    string db_bak = db_fname + ".bak";
    auto o_mask = umask(0117);
    int fd = open("/tmp/typtop.lock", O_WRONLY);
    struct flock* lock = (struct flock*)malloc(sizeof(struct flock));
    lock_file(fd, lock);
#endif
    std::fstream of(db_bak, ios::out | ios::binary);

    if(of.good())
        db.SerializeToOstream(&of);
    else {
        LOG_ERROR << "Could not open backup file for writing " << db_bak;
        // cerr << "Could not open backup file for writing\n" << strerror(errno) << endl;
    }

    if(rename(db_bak.c_str(), db_fname.c_str()) != 0) {
        LOG_ERROR << "Could not replace original db file " << db_fname;
    }
    umask(o_mask);
#ifdef WIN32
    throw("No idea what to do!")
#else
    unlock_file(fd, lock);
    close(fd);
#endif
    LOG_INFO << "db is saved";
}

TypTop::~TypTop() {
    if(db.IsInitialized())
        save();
    LOG_INFO << " -- TypTop END -- " << endl;
}


void TypTop::add_to_waitlist(const string &typo, time_t ts) {
    LOG_DEBUG_IF(db.w_size() < W_size) << "Increasing Waitlist size from "
                                       << db.w_size() << " to " << W_size;
    for (int i = db.w_size(); i < W_size; i++)
        db.add_w();
    string ctx;
    WaitlistEntry wlent;
    wlent.set_pw(typo);
    wlent.set_ts((int64_t)ts);

    pkobj.pk_encrypt(wlent.SerializeAsString(), ctx);
    int32_t curr_index = db.h().indexj();
    db.set_w(curr_index, ctx);
    curr_index = (curr_index + 1) % W_size;
    db.mutable_h()->set_indexj(curr_index);
}

void TypTop::fill_waitlist_w_garbage() {
    for (int i = 0; i < W_size; i++) {
        string b(DEFAULT_PW_LENGTH, 0);
        PRNG.GenerateBlock((byte *) b.data(), b.size());
        add_to_waitlist(b, -1); // ts = -1 for garbage strings
    }
}

void TypTop::reinitialize(const string &pw) {
    LOG_INFO << "Reinitializing the db.";
    initialize(pw);
}

void TypTop::initialize(const string &real_pw) {
    ConfigHeader *ch = db.mutable_ch();
    this->real_pw = real_pw;
    // - Set config header
    ch->set_install_id(get_install_id());
    pkobj.initialize();
    LOG_INFO << "Initializing the db ";
    ch->set_public_key(pkobj.serialize_pk());
    if (ch->global_salt().empty()) { // only change the salt if it is empty
        SecByteBlock global_salt((ulong)AES::BLOCKSIZE);
        PRNG.GenerateBlock(global_salt, global_salt.size());  // random element
        ch->set_global_salt((const char *) global_salt.data(), global_salt.size());
    } else {
        LOG_INFO << "Keeping the salt unchanged";
    }

    string sk_str = pkobj.serialize_sk();
    // cerr << __FUNCTION__ << " :: " << b64encode(sk_str) << endl;

    // --- Set the encryption header
    ench.set_pw(real_pw);
    ench.set_pw_ent(entropy(real_pw));
    std::vector<string> T_cache(T_size - 1);
    get_typos(real_pw, T_cache);
    T_cache.insert(T_cache.begin(), real_pw);  // the real password is always at the 0-th location
    assert(T_cache.size() == T_size);
    string _t, sk_ctx;

    for (int i = 0; i < T_size; i++) {
        if (T_cache[i].empty() || !meets_typo_policy(real_pw, T_cache[i], db.ch().tp())) { // generate random
            T_cache[i].resize(DEFAULT_PW_LENGTH, 0);
            PRNG.GenerateBlock((byte *) T_cache[i].data(), T_cache[i].size());
            if (!T_cache[i].empty()) LOGD << "Skipping: " << T_cache[i];
        } else {
            insert_into_log(T_cache[i], true, -1); // sets L
            LOGD << "Inserting: " << T_cache[i];
        }
        pwencrypt(T_cache[i], sk_str, sk_ctx);
        // LOG_DEBUG << "Inserting " << T_cache[i] << " at " << i;
        _insert_into_typo_cache(i, sk_ctx, (i == 0 ? INT_MAX : T_size - i));
#ifdef DEBUG
        // cerr << "Inserting -->" << T_cache[i] << endl;
        if(i>0) {
            assert(db.t(i) == sk_ctx);
            assert(pwdecrypt(T_cache[i], db.t(i), _t));
            assert(ench.freq(i) == T_size-i);
        }
#endif
    }
    permute_typo_cache(sk_str);
    Header *h = db.mutable_h();
    h->set_indexj(PRNG.GenerateWord32(0, W_size - 1)); // initialize the indexj to a random value
    assert(ench.freq_size() == T_size);
    string ench_ctx;
    pkobj.pk_encrypt(ench.SerializeAsString(), *(h->mutable_enc_header()));

// For debugging
#ifdef DEBUG
    string ench_str;
    pkobj.pk_decrypt(h->enc_header(), ench_str);  // For debugging
    assert (ench_str == ench.SerializeAsString()); // For debugging
#endif

    fill_waitlist_w_garbage();   // sets W
    db.mutable_h()->set_sys_state(SystemStatus::ALL_GOOD);
    assert(is_initialized());
    LOG_INFO << "DB is initialized.";
#ifdef DEBUG
    if (db.t_size() != ench.freq_size() ||
        db.t_size() != ench.last_used_size() ||
        ench.last_used_size() != T_size) {
        cerr << __FILE__ << __LINE__ << " : "
             << " ---> db.t=" << db.t_size() << ", freq=" << ench.freq_size()
             << " last_used=" << ench.last_used_size() << " T-size=" << T_size << endl;
        throw ("I am dying");
    }
    LOGD << "TypTop data-structure is initialized!" << endl;
#endif
}


void TypTop::insert_into_log(const string &pw, bool in_cache, time_t ts) {
    assert(!real_pw.empty());
    float _this_pw_ent = entropy(pw);
    size_t len = pw.size();
    // Why 10, that's the 3-quartile of RockYou dataset with passwords>6. 
    int pass_complexity = (len>10 || _this_pw_ent>32)?1:0;
    SecByteBlock g_salt((const byte *) db.ch().global_salt().data(), db.ch().global_salt().size());
    int edist = edit_distance(pw, real_pw);
    Log *l = db.mutable_logs()->add_l();
    l->set_in_cache(in_cache);
    l->set_istop5fixable(top5fixable(real_pw, pw));
    l->set_edit_dist(min(edist, 5));
    l->set_rel_entropy(_this_pw_ent - ench.pw_ent());
    l->set_pass_complexity(pass_complexity);
    l->set_tid(compute_id(g_salt, pw));
    l->set_ts((int64_t)ts);
    l->set_localtime(localtime());
    /** For small stats **/
    if (ts>0 && edist>0 && edist<5) {
        db.mutable_logs()->set_typos(db.logs().typos() + 1);
        if (in_cache)
            db.mutable_logs()->set_typos_saved(db.logs().typos_saved() + 1);
    }
}

int TypTop::is_typo_present(const string &pw, string &sk_str) const {
    int i = 0;
    for (i = 0; i < T_size; i++) {
        sk_str.clear();
        if (pwdecrypt(pw, db.t(i), sk_str)) { // match found
            break;
        }
    }
    return i;
}

bool TypTop::is_correct(const string &pw) const {
    string sk_str;
    bool ret = pwdecrypt(pw, db.t(0), sk_str);
    sk_str.clear();
    return ret;
}

/**
 * Checks the password in the TypTop cache.
 * 01. if pret == FIRST_TIME, then only reply if IsInitialized
 * 0b. if pret == SECOND_TIME, then only Initialize and return true.
 * 1. Check the pw against db.t()
 * 2. If match found, process waitlist.
 * 2a.
 * 3. If no match found add to waitlist
 * 3a.
 * @param pw: typed password (could be wrong)
 * @param were_right: The return from previous authentication mechanism, such as pam_unix.
 * @return Whether or not the entered password is allowable.
 */
bool TypTop::check(const string &pw, PAM_RETURN pret, bool isfork) {
    LOG_INFO << "Checking with typtop for FIRST/SECOND: " << pret;
    if(!is_initialized()) {
        if (pret == SECOND_TIME) {
            this -> initialize(pw);
            return true;
        } else {
            LOG_DEBUG << "DB is not initialized.";
            return false;
        }
    }
    if (pret == SECOND_TIME) {
        // Should have handled this pw submission in first time
        // Probably cause: password changed, so have to reinitialize the db.
        // TODO: How to detect old typo?
        this->reinitialize(pw);
        return true;
    }

    ench.Clear();
    string sk_str, enc_header_str;
    /* Standard book-keeping */
    db.mutable_h()->set_login_count(db.h().login_count() + 1);

    // check the password
    int i = is_typo_present(pw, sk_str);

    if (i == T_size) { // not found in the typo cache, so add to waitlist
        add_to_waitlist(pw, now());
        LOG_INFO << "Failed to find match in typocache: " << i;
        return false;
    } else { // match_found is true
        // cerr << __FUNCTION__ << " :: " << b64encode(sk_str) << endl;
        pkobj.set_sk(sk_str);
        // TODO: Verify whether or not this is the correct sk
        try {
            pkobj.pk_decrypt(db.h().enc_header(), enc_header_str);
            ench.ParseFromString(enc_header_str);
            this->real_pw = ench.pw();
            if (i > 0) {
                ench.set_freq(i, ench.freq(i) + 1);
                ench.set_last_used(i, now());
            }
            process_waitlist(sk_str);
            permute_typo_cache(sk_str);

            insert_into_log(pw, true, now());
            string ench_ctx, _t_ench_str;

            pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
            pkobj.pk_decrypt(ench_ctx, _t_ench_str);
            assert(_t_ench_str == ench.SerializeAsString());
            db.mutable_h()->set_enc_header(ench_ctx);
            ench.Clear();
            if(i == 0)
                LOG_INFO << "Accepting the real password!";
            else {
                if(db.ch().allowed_typo_login() && meets_typo_policy(this->real_pw, pw, db.ch().tp()))
                    LOG_INFO << "Accepting a typo!";
                else {
                    LOG_INFO << "Typo is rejected because of the allow_typo_log is "
                             << db.ch().allowed_typo_login();
                    LOG_INFO << " or does not meet the typo-policy"
                             << db.ch().tp().SerializePartialAsString();
                    return false;
                }
            }
            if(db.ch().allow_upload()){
#ifdef DEBUG
                send_log(1);
#else
                send_log(!isfork);
#endif
            }
            return true;
        } catch (exception &ex) {
            LOG_FATAL << "Exception: " << ex.what() << endl;
            LOG_ERROR << b64encode(enc_header_str) << endl;
            PkCrypto pkobj1; pkobj1.set_sk(sk_str);
            pkobj1.pk_decrypt(db.h().enc_header(), enc_header_str);
            return false;
        }
    }
}

void TypTop::_insert_into_typo_cache(const int index, const string &sk_ctx,
                                     const int freq) {
    LOG_DEBUG_IF(ench.freq_size()<T_size)<< "Increasing the Typocache size from "
                                         << db.t_size() << " to " << T_size;
    for(int i=db.t_size(); i<T_size; i++) // db.T can deviate, hence separately dealing with it.
        db.add_t();
    for (int i = ench.freq_size(); i < T_size; i++) { // assume two arrays (freq, last_used) are in sync
        ench.add_freq(-1);
        ench.add_last_used(-1);
    }
    assert(db.t_size() == T_size);

    db.set_t(index, sk_ctx);
    int64_t now_t = now();
    ench.set_freq(index, freq);
    ench.set_last_used(index, now_t);
}

/**
 * For security reason we should keep the typo cache permuted after
 * every time the cache is altered.
 */
void TypTop::permute_typo_cache(const string &sk_str) {
    std::random_device rd;
    uint32_t permutation_seed = rd();
    std::mt19937 g(permutation_seed);
    shuffle(db.mutable_t()->begin() + 1, db.mutable_t()->end(), g);
    g.seed(permutation_seed); // reseed the permutaion
    shuffle(ench.mutable_freq()->begin() + 1, ench.mutable_freq()->end(), g);
    g.seed(permutation_seed);
    shuffle(ench.mutable_last_used()->begin() + 1, ench.mutable_last_used()->end(), g);

    int64_t t_now = now();
    string sk_ctx;
    for (int i = 1; i < T_size; i++) { // don't remove real password
        if (t_now - ench.last_used(i) > db.ch().typo_expiry_time()) {
            string fake_pw(DEFAULT_PW_LENGTH, 0);
            PRNG.GenerateBlock((byte *) fake_pw.data(), fake_pw.size());
            pwencrypt(fake_pw, sk_str, sk_ctx);
            LOG_DEBUG << "Inserting " << fake_pw << " at " << i;
            _insert_into_typo_cache(i, sk_ctx, -1);
        }
    }
}

/**
 * 1. Decrypt the waitlist, add to log, and consolidate
 * 2. for each consolidated and validated entries
 *     try to insert in the typo cache
 */
void TypTop::process_waitlist(const string &sk_str) {
    LOG_DEBUG << "Processing waitlist" ;
    assert (!this->real_pw.empty());
    map<string, int> wl_typo;
    WaitlistEntry wlent;
    for (int i = 0; i < W_size; i++) {
        string wlent_str;
        pkobj.pk_decrypt(db.w(i), wlent_str);
        wlent.ParseFromString(wlent_str);
        if (wlent.ts() > 0) // no points logging the garbage of the Wait-list
            insert_into_log(wlent.pw(), false, wlent.ts());
        if (meets_typo_policy(real_pw, wlent.pw(), db.ch().tp())) {
            wl_typo[wlent.pw()] = wl_typo[wlent.pw()] + 1; // stl map initialized to 0 by default!!
        }
    }

    vector<int> freq_vec(ench.freq().begin(), ench.freq().end());
    auto freq_vec_sorted_idx = sort_indexes(freq_vec);
    for (auto e: wl_typo) {
        // cerr<< e.first << " :: " << e.second << endl;
        string pw = e.first;
        int freq = e.second;
        string sk_ctx;
        LOG_DEBUG << "Got typo: " << pw;
        for (auto i: freq_vec_sorted_idx) {
            // try to insert at i-th location
            if (win(ench.freq((int) i), freq)) {
                pwencrypt(pw, sk_str, sk_ctx);
                LOG_DEBUG << "Inserting " << pw << " at " << i;
                _insert_into_typo_cache((int) i, sk_ctx, max(freq, freq_vec[i] + 1));
#ifdef DEBUG
            string _t;
            assert(pwdecrypt(pw, db.t(i), _t));
#endif
                break;
            }
        }
        // add_to_typo_cache(e.first, e.second, sk_str, ench);
    }
    fill_waitlist_w_garbage();
}

void TypTop::print_log() {
    if(is_initialized()) {
        for(auto it: db.logs().l())
            cerr << it.DebugString() << endl;
    } else {
        cerr << "Db is not initialized. " << db.IsInitialized();
    }
}

void TypTop::allow_upload(bool b) {
    if(db.IsInitialized()) {
        db.mutable_ch()->set_allow_upload(b);
    }
}

void TypTop::allow_typo_login(bool b) {
    if(db.IsInitialized()) {
        db.mutable_ch()->set_allowed_typo_login(b);
    }
}

const TypoPolicy& TypTop::get_typo_policy() {
    return db.ch().tp();
}

void TypTop::set_typo_policy(int edit_cutoff, int abs_entcutoff, int rel_entcutoff) {
    TypoPolicy *tp = db.mutable_ch()->mutable_tp();
    if (edit_cutoff >= 0) tp->set_edit_cutoff(edit_cutoff);
    if (abs_entcutoff >= 0) tp->set_abs_entcutoff(abs_entcutoff);
    if (rel_entcutoff >= 0) tp->set_rel_entcutoff(rel_entcutoff);
}

#include "upload.cpp"
int TypTop::send_log(int test) {
    if (test == 0)
        if(fork() != 0) // in child make a network call
            return 0;
    if (!is_initialized()) {
        LOG_INFO << "DB is not initialized. Will send logs later.";
    } else if (db.logs().l_size() < 5) {
        LOG_INFO << "Not many logs (" << db.logs().l_size() << "). Will send logs later.";
    } else {
        LOG_INFO << "sending logs \n";
        int ret = send_log_to_server(db.ch().install_id(),
                                     b64encode(db.logs().SerializeAsString()),
                                     test);
        if (ret == 1) {
            db.mutable_logs()->clear_l();
            return 1;
        }
    }
    return 0;
}

int typo_stats(const Logs& L, int* saved) {
    int t=0, s=0;
    *saved = L.typos_saved();
    return L.typos();
    for (Log l: L.l()) {
        if(l.edit_dist()>0 && l.edit_dist() < 4) {
            t++;
            if (l.in_cache())
                s++;
        }
    }
    *saved = s;
    return t;
}

void TypTop::status() const {
    int saved;
    int typo_count = typo_stats(db.logs(), &saved);
    cout << "\nTypTop: A smart password checker" << endl
         << "  Version: " << typtop_VERSION_MAJOR << "." << typtop_VERSION_MINOR << endl
         << "  Install-id: " << db.ch().install_id() << endl
         << "  Login attempts: " << db.h().login_count() << endl
         << "  Typos made: " << typo_count << endl
         << "  Logins saved by TypTop: " << saved << endl
         << "  Volunteer for the study: " << db.ch().allow_upload() << endl
         << "  Allow login with typos: " << db.ch().allowed_typo_login() << endl;
    const typtop::TypoPolicy& tp = db.ch().tp();
    cout << "  TypoPolicy: \n"
         << "\t EditDistance Cutoff: " << tp.edit_cutoff() << endl
         << "\t Absolute Entropy Cutoff: " << tp.abs_entcutoff() << endl
         << "\t Relative Entropy Cutoff: " << tp.rel_entcutoff() << endl << endl;
#ifdef DEBUG
    cout << "(Debug is on)\n";
#endif
}

