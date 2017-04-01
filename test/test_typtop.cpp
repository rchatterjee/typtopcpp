//
// Created by rahul on 3/30/17.
//

#include "src/typtop.h"
#include "catch.hpp"

#define DEBUG 1

const string _db_fname = "./test_typtop_db";
const vector<string> pws = {
        "hello_pass", // 0, ed=0
        "Hello_pass",  // 1, ed=1
        "hello_pass1", // 2, ed=1
        "HELLO_PASS",  // 3, ed=1
        "hlelo_pass", // 4, ed=1
        "Hello_Pass",  // 5, ed=2
};
const string install_id = get_install_id();
const int32_t infinity = INT_MAX;
#define times(n, code_block) {for(int _ti=0; _ti<n; _ti++) code_block;}

class TypTopTest : public TypTop {
public:
    TypTopTest() : TypTop(_db_fname, pws[0]) {};
    using TypTop::add_to_waitlist;
    using TypTop::add_to_typo_cache;
    using TypTop::get_db;
    using TypTop::get_ench;
    using TypTop::get_pkobj;
    using TypTop::permute_typo_cache;
    inline void initialize(const string& pw) { TypTop::initialize(_db_fname, pw);}
};

TEST_CASE("typtop") {

    SECTION("typtop_util functions") {
        SECTION("edit_distance") {
            byte b[] = {0x32, 0xf4, 0x32, 0x65, 0xff};
            string b_str((char *) b, 5);
            REQUIRE(edit_distance(pws[0], pws[0]) == 0);
            CHECK(edit_distance(b_str, b_str) == 0);
            CHECK(edit_distance(pws[0], pws[1]) == 1);
            CHECK(edit_distance(pws[0], pws[2]) == 1);
            CHECK(edit_distance(pws[0], pws[3]) == 1);
            CHECK(edit_distance(pws[0], pws[4]) == 1);
            CHECK(edit_distance(pws[0], pws[5]) == 2);
        }
        SECTION("get_typos") {
            vector<string> typos(10);
            // hello_pass
            vector<string> should_be = {
                    "Hello_pass", "HELLO_PASS", "hello_pass1", "ello_pass", "hello_pas",
                    "hello_pass`"
            };
            get_typos(pws[0], typos);
            REQUIRE(typos.size() == 10);
            CHECK(std::find(typos.begin(), typos.end(), pws[0]) == typos.end());
            for (auto ti: should_be) {
                CHECK(std::find(typos.begin(), typos.end(), ti) != typos.end());
            }
        }
        SECTION("win(f_o, f_n)") {
            REQUIRE(win(0, INT_MAX));
            REQUIRE_FALSE(win(-1, 0));
            REQUIRE(win(-1, 1));
            REQUIRE(win(-1, INT_MAX));
            REQUIRE_FALSE(win(INT_MAX, 0));
            REQUIRE_FALSE(win(INT_MAX, INT_MAX));
            REQUIRE_FALSE(win(INT_MAX - 4, 5));
            CHECK_FALSE(win(1, 0));
            //CHECK_THROWS(win(0, 0));
        }
        SECTION("meets_typo_policy") {
            CHECK(meets_typo_policy(pws[0], pws[0]));
            CHECK(meets_typo_policy(pws[3], swapcase(pws[3])));
            CHECK(meets_typo_policy(pws[0], pws[3])); // edit distance >1
            CHECK_FALSE(meets_typo_policy(pws[0], pws[5])); // edit distance >1
            CHECK_FALSE(meets_typo_policy(pws[0].substr(6), pws[0].substr(0, 6)));
            CHECK_FALSE(meets_typo_policy(pws[0].substr(0, 6), pws[1].substr(0, 6)));
        }
    }

    SECTION("Test TypTop DB") {
        remove(_db_fname.c_str()); // fresh initialization
        TypTopTest tp;
        const typtopDB &db = tp.get_db();
        const PkCrypto &pkobj = tp.get_pkobj();
        REQUIRE(db.w_size() == W_size);
        REQUIRE(db.t_size() == T_size);
        REQUIRE(db.h().sys_state() == SystemStatus::ALL_GOOD);

        SECTION("Install id") {
            CHECK(tp.this_install_id() == install_id);
            CHECK(db.ch().install_id() == install_id);
        }

        SECTION("post install checks") {
            EncHeaderData ench;
            string ench_str, ctx, rdata, sk_str;

            PkCrypto mut_pkobj(pkobj);
            REQUIRE(pwdecrypt(pws[0], db.t(0), sk_str));
            mut_pkobj.set_sk(sk_str);
            // decrypt real_pw
            mut_pkobj.pk_decrypt(db.h().enc_header(), ench_str);
            REQUIRE(ench.ParseFromString(ench_str));
            REQUIRE(ench.freq_size() == T_size);
            REQUIRE(ench.last_used_size() == T_size);

            SECTION("check permutation") {
                vector<string> T(db.t().begin(), db.t().end());
                tp.permute_typo_cache(sk_str);
                const EncHeaderData &new_ench = tp.get_ench();
                CHECK(db.t(0) == T[0]); // Fist index should always match
                CHECK(new_ench.last_used(0) == ench.last_used(0));
                CHECK(new_ench.freq(0) == ench.freq(0));
                int j = 0;
                bool at_least_permuted = false;
                for (int i = 0; i < T_size; i++) {
                    for (j = 0; j < T_size; j++) {
                        if (new_ench.freq(j) == ench.freq(i)) {
                            CHECK(new_ench.last_used(j) == ench.last_used(i));
                            CHECK(T[i] == db.t(j));
                            at_least_permuted |= (i != j);
                            // cerr << i << " <<-->> " << j << endl;
                            break;
                        }
                    }
                    REQUIRE(j < T_size);
                }
                // REQUIRE(at_least_permuted); // TODO: Fix permute cache function;
            }

            SECTION("Verify inserted typos") {
                vector<string> typos(T_size);
                get_typos(pws[0], typos);
                string sK_str;
                typos.insert(typos.begin(), pws[0]);
                REQUIRE(pwdecrypt(pws[0], db.t(0), sk_str));
                for(int j=1; j<T_size; j++) {
                    size_t i=0;
                    for(i=0; i<typos.size(); i++){
                        // cerr << "<<-- checking >> " << typos[i] << endl;
                        if (pwdecrypt(typos[i], db.t(j), sk_str))
                            break;
                    }
                    CHECK(i < typos.size());
                }
            }

            SECTION("Check(pw)") {
                CHECK(db.h().sys_state() == SystemStatus::ALL_GOOD);
                mut_pkobj.pk_decrypt(db.h().enc_header(), ench_str);
                CHECK(tp.check(pws[0], false));
                ench.Clear();
                ench.ParseFromString(ench_str);
                CHECK(ench.pw() == pws[0]);
                CHECK(tp.check(pws[0], true));
            }

            SECTION("step-by-step 'check' function") {
                ench.Clear();
                string enc_header_str;
                /* Standard book-keeping */
                CHECK(pwdecrypt(pws[0], db.t(0), sk_str));
                mut_pkobj.set_sk(sk_str);
                mut_pkobj.pk_decrypt(db.h().enc_header(), enc_header_str);
                ench.ParseFromString(enc_header_str);
                CHECK(ench.pw() == pws[0]);

                CHECK(ench.IsInitialized());
                string ench_ctx, _t_ench_str;
                pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
                pkobj.pk_decrypt(ench_ctx, _t_ench_str);
                // db.mutable_h()->set_enc_header(ench_ctx);
                CHECK(_t_ench_str == ench.SerializeAsString());
                ench.Clear();
            }
        }

        SECTION("add_to_waitlist") {
            SECTION("one typo add") { // Please make sure added typo is not in the typo cache
                int indexj = db.h().indexj();
                tp.add_to_waitlist("Blahblah", now());
                CHECK((indexj + 1) % W_size == db.h().indexj());
                CHECK(db.w_size() == W_size);
            }
            SECTION("add 20 typos") {
                int indexj = db.h().indexj();
                for (int i = 0; i < W_size; i++)
                    tp.add_to_waitlist("Blahblah", now());
                REQUIRE(indexj == db.h().indexj());
                REQUIRE(db.w_size() == W_size);
            }
        }
    }

    SECTION("persistence of the db on re-reading") {
        TypTopTest tp1;
        tp1.save();
        TypTopTest tp2;
        const typtopDB db1 = tp1.get_db(), db2 = tp2.get_db();
        // test CH
        REQUIRE(db1.ch().DebugString() == db2.ch().DebugString());
        // test H
        REQUIRE(db1.h().SerializeAsString() == db2.h().SerializeAsString());
        // test W
        for (int i = 0; i < W_size; i++)
            REQUIRE(db1.w(i) == db2.w(i));
        // test T
        for (int i = 0; i < T_size; i++)
            REQUIRE(db1.t(i) == db2.t(i));

        // test L
        REQUIRE(db1.l_size() == db2.l_size());
        for (int i = 0; i < db1.l_size(); i++)
            REQUIRE(db1.l(i).SerializeAsString() == db2.l(i).SerializeAsString());

        string s1 = b64encode(tp1.get_db().SerializeAsString());
        string s2 = b64encode(tp2.get_db().SerializeAsString());
        REQUIRE(s1.length() == s2.length());
        REQUIRE(s1.substr(0, 100) == s2.substr(0, 100));
        CHECK(s1 == s2);
    }

    SECTION("Test TypTop Public functions") {
        remove(_db_fname.c_str());
        TypTopTest tp;
        const typtopDB &db = tp.get_db();
        REQUIRE(db.ch().install_id() == install_id);

        SECTION("check") {
            REQUIRE(tp.check(pws[0], false));
            REQUIRE(tp.check(pws[0], true));
            CHECK(tp.check(pws[1], false));
            CHECK(tp.check(pws[2], false));
            CHECK(tp.check(pws[3], false));
            CHECK_FALSE(tp.check(pws[4], false));
            CHECK_FALSE(tp.check(pws[5], false));
        }

        SECTION("try inserting a typo with real pw") {
            REQUIRE(tp.check(pws[0], true));
            times(5, CHECK_FALSE(tp.check(pws[4], false)));
            times(5, CHECK_FALSE(tp.check(pws[5], false)));
            REQUIRE(tp.check(pws[0], true));
            CHECK(tp.check(pws[4], false));
            CHECK_FALSE(tp.check(pws[5], false));
        }

        SECTION("try inserting a typo with typo") {
            REQUIRE(tp.check(pws[1], true));
            times(5, CHECK_FALSE(tp.check(pws[4], false)));
            times(5, CHECK_FALSE(tp.check(pws[5], false)));
            REQUIRE(tp.check(pws[1], false));
            CHECK(tp.check(pws[4], false));
            CHECK_FALSE(tp.check(pws[5], false));
        }
    }

    SECTION("Typtop test log entries") {

    }

    SECTION("Typtop extra utilities") {
        // TODO: Other extra features
    }

    SECTION("Long term use of typtop.") {

    }

}

