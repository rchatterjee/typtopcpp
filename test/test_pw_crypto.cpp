//
// Created by rahul on 3/28/17.
//

#include "pw_crypto.h"
#include "catch.hpp"
#include "db.pb.h"

using std::vector;

string random_msg() {
    SecByteBlock s(50);
    PRNG.GenerateBlock(s.data(), s.size());
    return string(s.begin(), s.end());
}

void get_random_ench(typtop::EncHeaderData& ench) {
    string pw(20, 0);
    PRNG.GenerateBlock((byte*)pw.data(), 20);  // might throw segfault
    ench.set_pw(pw);
    ench.set_pw_ent((float)-93.346);
    for (int i = 0; i < 10; i++) {
        ench.add_freq(3);
        ench.add_last_used(13123);
    }
    ench.set_freq(2, 24);
}

TEST_CASE("pw_crypto") {
    PwPkCrypto pkobj;
    string large_msg = "very large message";
    for(int i=0; i < 2; i++) large_msg += large_msg;
    SECTION("pad-unpad") {
        string s("Hello Brother");
        string pad_s = pkobj.pad(s);
        CHECK(pad_s.size() == pkobj.len_limit());
        CHECK(pad_s != s);
        string unpad_s = pkobj.unpad(pad_s);
        CHECK(unpad_s == s);

        s = large_msg;
        pad_s = pkobj.pad(s);
        CHECK(pad_s.size() == pkobj.len_limit());
        CHECK(pad_s != s);
        unpad_s = pkobj.unpad(pad_s);
        CHECK(unpad_s == s.substr(0, pkobj.len_limit()));
    }

    SECTION("PwPkCrypto.basic") {
        PwPkCrypto pkobj;
        string sk_str = b64decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAg"\
                                  "EBBCAUsnXuu6Zj3CjT0Xd6BXOqg5jB7zgWfvCGsjC3NZRaQw");
        pkobj.set_sk(sk_str, true); // generate pk
        string msg = random_msg(), ctx, rdata;
        pkobj.pk_encrypt(msg, ctx);
        pkobj.pk_decrypt(ctx, rdata);
        REQUIRE(b64encode(rdata) == b64encode(msg));

        SECTION("0: pk encrypt-decrypt") {
            byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
            string msgs[] = {
                    "Hey here I am",
                    "aaaaaaa",
                    {_t1, _t1 + 6},
                    ""
            };
            for (int i = 0; i < 3; i++) {
                pkobj.pw_pk_encrypt(msgs[i], ctx);
                pkobj.pw_pk_decrypt(ctx, rdata);
                REQUIRE(rdata.size() == msgs[i].size());
                CHECK(rdata == msgs[i]);
            }
        }
    }

    SECTION("Large message") {
        PwPkCrypto pkobj;
        pkobj.initialize();
        string ctx, rdata;
        string msg = "Hello brother";
        pkobj.pw_pk_encrypt(msg, ctx);
        // 85 comes from the other overheads
        CHECK(ctx.length() <= pkobj.len_limit() * 2);
        cout << "Ciphertext size: " << ctx.size() << endl;
        pkobj.pw_pk_decrypt(ctx, rdata);
        CHECK(rdata.size() <= pkobj.len_limit());
    }
}

TEST_CASE("pk_crypto") {

    SECTION ("b64 encode decode") {
        byte _t1[] = {0x12, 0x12, 0x45, 0xf2, 0x34};
        vector<SecByteBlock> raw_bytes = {
                SecByteBlock((const byte *) "aaa13", 5),
                SecByteBlock((const byte *) "", 0),
                SecByteBlock(_t1, 5)
        };
        for (size_t i = 0; i < raw_bytes.size(); i++) {
            string _t_encoded, _t_byte_str;
            string res = b64decode(b64encode(raw_bytes[i]));
            // cout << "~~> " << raw_bytes[i] << endl;
            int b = raw_bytes[i] == res.data();
            if (b != 0) {
                cout << "i: " << i << endl;
                cout << res << endl;
                cout << raw_bytes[i].data() << endl;
            }
            REQUIRE(b == 0);
            CHECK(b64encode(raw_bytes[i]) == b64encode(raw_bytes[i]));
        }
    }

    SECTION("harden_pw") {
        string pw = "SecretPass";
        SecByteBlock salt, key, nkey;
        harden_pw(pw, salt, key);
        harden_pw(pw, salt, nkey);
        CHECK(b64encode(key) == b64encode(nkey));
        nkey.resize(0);
        harden_pw(pw + "1", salt, nkey);
        CHECK_FALSE(b64encode(key) == b64encode(nkey));
        salt.resize(0);
        nkey.resize(0);
        harden_pw(pw, salt, nkey);
        nkey.resize(0);
        harden_pw(pw, salt, nkey);
        CHECK_FALSE(b64encode(key) == b64encode(nkey));
    }

    SECTION("pwencrypt-decrypt") {
        string pw = "Super secret pw";
        byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
        string s(_t1, _t1 + 6);
        vector<string> msgs = {
                "Hey here I am",
                "aaaaaaa",
                "",
                ""
        };
        string ctx, rdata;
        msgs[3] = string((char *) _t1, 6);
        for (size_t i = 0; i < 20; i++) {
            if(msgs.size() <= i) {
                SecByteBlock sb(300);
                PRNG.GenerateBlock(sb.data(), sb.size());
                msgs.push_back(string(sb.begin(), sb.end()));
            }
            pwencrypt(pw, msgs[i], ctx);
            REQUIRE(pwdecrypt(pw, ctx, rdata));
            REQUIRE(rdata == msgs[i]);
            REQUIRE(ctx != msgs[i]);
            REQUIRE(ctx.size() > msgs[i].size());
            REQUIRE_FALSE(pwdecrypt(pw + ' ', ctx, rdata));
        }
    }


    SECTION("PkCrypto.basic") {
        PkCrypto pkobj;
        string sk_str = b64decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAg"\
                                  "EBBCAUsnXuu6Zj3CjT0Xd6BXOqg5jB7zgWfvCGsjC3NZRaQw");

        pkobj.set_sk(sk_str, true); // generate pk
        string msg = random_msg(), ctx, rdata;
        pkobj.pk_encrypt(msg, ctx);
        pkobj.pk_decrypt(ctx, rdata);
        REQUIRE(b64encode(rdata) == b64encode(msg));

        SECTION("0: pk encrypt-decrypt") {
            byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
            string msgs[] = {
                    "Hey here I am",
                    "aaaaaaa",
                    {_t1, _t1 + 6},
                    ""
            };
            for (int i = 0; i < 3; i++) {
                pkobj.pk_encrypt(msgs[i], ctx);
                pkobj.pk_decrypt(ctx, rdata);
                REQUIRE(rdata == msgs[i]);
            }
        }

        SECTION("1: pk load and dump key") {
            PkCrypto pkobj1;
            pkobj1.set_pk(pkobj.serialize_pk());
            PkCrypto pkobj2;
            pkobj2.set_sk(pkobj.serialize_sk());
            pkobj1.pk_encrypt(msg, ctx);
            pkobj2.pk_decrypt(ctx, rdata);
            REQUIRE(rdata == msg);
        }

        SECTION("2: Cipher must be in correct format") {
            pkobj.pk_encrypt(msg, ctx);
            CHECK_THROWS(pkobj.pk_decrypt(ctx + "adfasdf", rdata));
            CHECK(rdata != msg);
            CHECK(rdata.find(msg) == string::npos);
        }

        /*SECTION("Check a weird failing case") {
            string sk_str = b64decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBHYss"\
            "FAMNGU5ZNpGrCBRsHmxTC_LGiQZEYhlQj6QZuLA");
            pkobj.set_sk(sk_str);
            string ench_ctx = b64decode("BHSzINxb56rx1M3np2KtMMgjfmxvwbuHgO1o1JfOJb5KxUaO6GWf"\
            "4wM5E8iyYOzH7lMtUeJGGNvStBSKMJ9wpHIj38tvlzfA6awL3bgQh94558BtbKYVbW3CaKpCE8AuKlkM8y"\
            "N2C-bMTzHP--Y-M8jZP-lGXH1Mozv-loRKh9tx0n9fKBZ-v5vO88rsNeU530iGGDMd4zctWqGioNrbKrc");
            string ench_str;
            pkobj.pk_decrypt(ench_ctx, ench_str);
            typtop::EncHeaderData ench;
            ench.ParseFromString(ench_str);
            cerr << ench.pw() << endl;
        }*/

        SECTION("Decrypt with wrong key") {
            pkobj.pk_encrypt(msg, ctx);
            pkobj.initialize();
            CHECK_THROWS(pkobj.pk_decrypt(ctx, rdata));
            CHECK_FALSE(rdata == msg);
        }

        SECTION("pk_encrypt-decrypt long messages") {
            msg.resize(20000, 76);
            pkobj.pk_encrypt(msg, ctx);
            pkobj.pk_decrypt(ctx, rdata);
            CHECK(b64encode(rdata) == b64encode(msg));
        }

        SECTION("pk encrypt decrypt many messages") {
            msg.resize(100);
            for (size_t i = 0; i < 50; i += 1) {
                PRNG.GenerateBlock((byte *) msg.data(), msg.size());
                pkobj.pk_encrypt(msg, ctx);
                pkobj.pk_decrypt(ctx, rdata);
                CHECK(rdata == msg);
                if (i % 4 == 0) {
                    string pk = pkobj.serialize_pk();
                    pkobj.set_sk(pkobj.serialize_sk());
                    CHECK(pkobj.serialize_pk() == pk);
                }
            }
        }

        SECTION("pk_encrypt with google protobuf") {
            typtop::EncHeaderData ench;
            get_random_ench(ench);
            string ench_str, ench_ctx;
            pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
            pkobj.pk_decrypt(ench_ctx, ench_str);
            CHECK(ench_str == ench.SerializeAsString());

            typtop::EncHeaderData o_ench;
            o_ench.ParseFromString(ench_str);
            PkCrypto pkobj1;
            pkobj1.set_sk(pkobj.serialize_sk());
            pkobj1.set_pk(pkobj.serialize_pk());
            ench_ctx.clear();
            ench_str.clear();
            pkobj1.pk_encrypt(o_ench.SerializeAsString(), ench_ctx);
            pkobj1.pk_decrypt(ench_ctx, ench_str);
            CHECK(ench_str == o_ench.SerializeAsString());
        }
    }


    SECTION("Serialization") {
        PkCrypto pkobj, pkobj1, pkobj2;
        pkobj.initialize();
        string ctx, rdata, msg = "Message from God!!";
        string sk = pkobj.serialize_sk();
        string pk = pkobj.serialize_pk();

        SECTION("check pk for multiple set_sk with same sk") {
            REQUIRE(pkobj.serialize_pk() == pk);
            pkobj1.set_sk(pkobj.serialize_sk());
            CHECK(b64encode(pkobj1.serialize_sk()) == b64encode(sk));
            pkobj1.set_pk(pkobj.serialize_pk());
            CHECK(b64encode(pkobj1.serialize_pk()) == b64encode(pk));

            pkobj1.set_sk(pkobj.serialize_sk());
            pkobj1.set_pk(pk);
            CHECK(b64encode(pkobj1.serialize_pk()) == b64encode(pk));
        }

        SECTION("check uninitialized keys") {
            CHECK_THROWS(pkobj1.pk_encrypt(sk, ctx));
            CHECK_FALSE(pkobj1.can_decrypt());
            CHECK_FALSE(pkobj1.can_encrypt());
        }
        SECTION("set_sk and set_pk") {
            pkobj1.set_sk(sk);
            CHECK(pkobj1.can_decrypt());
            CHECK_FALSE(pkobj1.can_encrypt());
            pkobj1.set_pk(pk);
            CHECK(pkobj1.can_decrypt());
            CHECK(pkobj1.can_encrypt());
        }
        SECTION("check wrong keys") {
            CHECK_THROWS(pkobj.set_pk("adfafasdf"));
            CHECK_THROWS(pkobj.set_sk("adfafasdf"));
        }
        SECTION("Interoperability"){
            pkobj.pk_encrypt(msg, ctx);
            pkobj.pk_decrypt(ctx, rdata);
            REQUIRE(rdata == msg);
            pkobj2.set_pk(pk); pkobj1.set_sk(sk);
            pkobj1.pk_decrypt(ctx, rdata);
            CHECK(rdata == msg);
            pkobj2.pk_encrypt(msg, ctx);
            pkobj1.pk_decrypt(ctx, rdata);
            CHECK(rdata == msg);
        }
    }
}
