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
using namespace typtop;

const int W_size = 20;
const int T_size = 5 + 1; // 1 for the real password

class TypTop {
private:
    typtopDB db;
    EncHeaderData ench;
    string db_fname;
    PkCrypto pkobj;
    string real_pw;   // secure object; carefully delete it once done
    void _insert_into_typo_cache(const int index, const string &sk_ctx, const int freq);

public:
    TypTop(const string& _db_fname, const string& real_pw="");
    ~TypTop();
    bool check(const string& pw, bool were_right=false);
    const string& this_install_id() const { return db.ch().install_id();}
    void save() const;

protected:
    void fill_waitlist_w_garbage();
    void initialize(const string& _db_fname, const string& pw);
    void insert_into_log(const string& pw, bool in_cache, int64_t ts);
    void add_to_waitlist(const string& pw, int64_t ts);
    void process_waitlist(const string& sk_str);
    void add_to_typo_cache(const string &pw, const int freq, const string &sk_str);
    void permute_typo_cache(const string& sk_str);

    // For testing
    inline const typtopDB& get_db(){ return db; }
    inline const PkCrypto& get_pkobj(){return pkobj;}
    inline const EncHeaderData& get_ench(){return ench;}
};


#endif //TYPTOP_C_TYPTOP_H
