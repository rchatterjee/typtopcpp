/**
 *
 * Created by Rahul Chatterjee on 3/28/17.
 * Main TyptopDB related functions are given here.
 * First, do the initialization
 */


#ifndef TYPTOP_C_TYPTOP_H
#define TYPTOP_C_TYPTOP_H

#include "pw_crypto.h"
#include "db.pb.h"
#include "typo_util.hpp"
#include "plog/Log.h"
#include "typtopconfig.h"


#ifndef TYPTOP_LOG_FILE
#define TYPTOP_LOG_FILE "/tmp/typtop.log"
#endif

using namespace typtop;

const int W_size = 20;
const int T_size = 5 + 1; // 1 for the real password

inline void setup_logger(plog::Severity severity) {
    const size_t MAX_LOG_FILE_SIZE = size_t(1e6); // 1 MB
#ifdef DEBUG
    plog::init(severity, TYPTOP_LOG_FILE"_test", MAX_LOG_FILE_SIZE, 1);
#else
    plog::init(severity, TYPTOP_LOG_FILE, MAX_LOG_FILE_SIZE, 1);
#endif
}

enum PAM_RETURN {
    FIRST_TIME = 1, // the pam_unix return is not known
    SECOND_TIME = 2 // pam_unix is true for sure
};

class TypTop {
private:
    typoDB db;
    EncHeaderData ench;
    string db_fname;
    PkCrypto pkobj;
    string real_pw;   // secure object; carefully delete it once done
    void _insert_into_typo_cache(const int index, const string &sk_ctx, const int freq);

public:
    TypTop(const string& _db_fname);
    ~TypTop();
    bool check(const string& pw, PAM_RETURN pret);
    const string& this_install_id() const { return db.ch().install_id();}
    void save() const;
    int is_typo_present(const string& pw, string& sk_str) const;
    bool is_correct(const string& pw) const;
    inline bool is_initialized() const { return db.IsInitialized(); }
    void print_log();
    int send_log(void);
    void allow_upload(bool b);
    void allow_typo_login(bool b);
    void status() const;
    void set_typo_policy(int edit_cutoff, int abs_entcutoff, int rel_entcutoff);

protected:
    void fill_waitlist_w_garbage();
    void initialize(const string& pw);
    void reinitialize(const string& pw);
    void insert_into_log(const string& pw, bool in_cache, time_t ts);
    void add_to_waitlist(const string& pw, time_t ts);
    void process_waitlist(const string& sk_str);
    void permute_typo_cache(const string& sk_str);

    // For testing
    inline const typoDB& get_db(){ return db; }
    inline const PkCrypto& get_pkobj(){return pkobj;}
    inline const EncHeaderData& get_ench(){return ench;}

};


#endif //TYPTOP_C_TYPTOP_H
