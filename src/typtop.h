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
const int T_size = 5;

class TypTop {
private:
    typtopDB db;
    string db_fname;
    PkCrypto pkobj;
    string real_pw;   // secure object; carefully delete it once done
public:
    TypTop(const string& _db_fname, const string& real_pw="");
    ~TypTop();

protected:
    void fill_waitlist_w_garbage();
    void initialize(const string& _db_fname, const string& pw);
    void insert_into_log(const string& pw, bool in_cache, int ts);
};


#endif //TYPTOP_C_TYPTOP_H
