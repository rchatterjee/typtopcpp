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
using namespace typtop;

const int W_size = 20;
const int T_size = 5 + 1; // 1 for the real password

class TypTop {
private:
    typtopDB db;
    string db_fname;
    PkCrypto pkobj;
    string real_pw;   // secure object; carefully delete it once done
public:
    TypTop(const string& _db_fname, const string& real_pw="");
    ~TypTop();
    bool check(const string& pw, bool were_right=false);

protected:
    void fill_waitlist_w_garbage();
    void initialize(const string& _db_fname, const string& pw);
    void insert_into_log(const string& pw, bool in_cache, int64_t ts);
    void on_correct_pw(const string& pw);
    void add_to_waitlist(const string& pw, int64_t ts);
    void process_waitlist(const string& sk_str, EncHeaderData& ench);
    void add_to_typo_cache(const string &pw, const int freq, const string &sk_str, EncHeaderData &ench);
    void permute_typo_cache(EncHeaderData& ench, const string& sk_str);
    void insert_to_typo_cache(const int index, const string& sk_ctx, const int freq, EncHeaderData& ench);
};


#endif //TYPTOP_C_TYPTOP_H
