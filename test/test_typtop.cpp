//
// Created by rahul on 3/30/17.
//

#include "src/typtop.h"
#include "catch.hpp"

#define DEBUG 1

const string _db_fname = "./test_typtop_db";
const string pws[] = {
        "hello_pass", // 0
        "Hello_pass",  // 1
        "hello_pass1", // 2
        "Hello_Pass",  // 3
        "HELLO_PASS"  // 4
};
const string install_id = get_install_id();
const int32_t infinity = INT_MAX;

class TypTopTest : public TypTop {
public:
    TypTopTest() : TypTop(_db_fname, pws[0]) {};
    using TypTop::add_to_waitlist;
    using TypTop::add_to_typo_cache;
    using TypTop::get_db;
    using TypTop::get_ench;
    using TypTop::get_pkobj;
    using TypTop::permute_typo_cache;
};

TEST_CASE("Typtop library functions") {

    SECTION("typtop_util functions") {
        SECTION("edit_distance") {
            byte b[] = {0x32, 0xf4, 0x32, 0x65, 0xff};
            string b_str((char *) b, 5);
            REQUIRE(edit_distance(pws[0], pws[0]) == 0);
            CHECK(edit_distance(b_str, b_str) == 0);
            CHECK(edit_distance(pws[0], pws[1]) == 1);
            CHECK(edit_distance(pws[0], pws[3]) == 2);
            CHECK(edit_distance(pws[0], pws[4]) == 1);
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
            CHECK_FALSE(meets_typo_policy(pws[0], pws[3])); // edit distance >1
            CHECK_FALSE(meets_typo_policy(pws[0].substr(6), pws[0].substr(0,6)));
            CHECK_FALSE(meets_typo_policy(pws[0].substr(0,6), pws[1].substr(0,6)));
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
            // pkobj.pk_decrypt(db.h().enc_header(), ench_str);
            PkCrypto mut_pkobj(pkobj);
            REQUIRE(pwdecrypt(pws[0], db.t(0), sk_str));
            mut_pkobj.set_sk(sk_str);
            // decrypt real_pw
            mut_pkobj.pk_decrypt(db.h().enc_header(), ench_str);
            REQUIRE(ench.ParseFromString(ench_str));
            REQUIRE(ench.freq_size() == T_size);
            REQUIRE(ench.last_used_size() == T_size);

            SECTION("check permutation"){
                vector<string> T(db.t().begin(), db.t().end());
                tp.permute_typo_cache(sk_str);
                const EncHeaderData& new_ench = tp.get_ench();
                CHECK(db.t(0) == T[0]); // Fist index should always match
                CHECK( new_ench.last_used(0) == ench.last_used(0) );
                CHECK( new_ench.freq(0) == ench.freq(0) );
                int j=0;
                bool at_least_permuted = false;
                for(int i=0; i<T_size; i++) {
                    for(j=0; j<T_size; j++) {
                        if(new_ench.freq(j) == ench.freq(i)){
                            CHECK( new_ench.last_used(j) == ench.last_used(i) );
                            CHECK( T[i] == db.t(j) );
                            at_least_permuted |= (i!=j);
                            cerr << i << " <<-->> " << j << endl;
                            break;
                        }
                    }
                    REQUIRE( j<T_size );
                }
                REQUIRE( at_least_permuted );
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
        }
        /*
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

            SECTION("persistence of the db on re-reading") {
                TypTopTest tp1;
                REQUIRE(db.SerializeAsString() == tp1.get_db().SerializeAsString());
            }
        }*/
        CHECK(db.w_size() == W_size);
        CHECK(db.t_size() == T_size);
        CHECK(db.ch().install_id() == install_id);
    }

//    SECTION("Test basics") {
//        TypTopTest tp;
//        const typtopDB &db = tp.get_db();
//        CHECK(db.ch().install_id() == install_id);
//        REQUIRE(tp.check(pws[0], false));
//        CHECK(tp.check(pws[1], false));
//        CHECK(tp.check(pws[2], false));
//        CHECK_FALSE(tp.check(pws[3], false));
//    }
}

