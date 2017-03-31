//
// Created by rahul on 3/28/17.
//

#include "src/pw_crypto.h"
#include "catch.hpp"
#include "db.pb.h"

using std::vector;

TEST_CASE("finv(f(m)) == m", "[pw_crypto]") {
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
            REQUIRE(b64encode(raw_bytes[i]) == b64encode(raw_bytes[i]));
            CHECK( b == 0 );
        }
    }

    SECTION("harden_pw") {
        string pw = "SecretPass";
        SecByteBlock salt, key, nkey;
        harden_pw(pw, salt, key);
        harden_pw(pw, salt, nkey);
        CHECK(b64encode(key) == b64encode(nkey));
        nkey.resize(0);
        harden_pw(pw+"1", salt, nkey);
        CHECK_FALSE(b64encode(key) == b64encode(nkey));
        salt.resize(0);nkey.resize(0);
        harden_pw(pw, salt, nkey); nkey.resize(0);
        harden_pw(pw, salt, nkey);
        CHECK_FALSE(b64encode(key) == b64encode(nkey));
    }

    SECTION("pwnecrypt decrypt") {
        string pw = "Super secret pw";
        byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
        string s(_t1, _t1+6);
        string msgs[] = {
                "Hey here I am",
                "aaaaaaa",
                "",
                ""
        };
        msgs[3] = string((char*)_t1, 6);
        for(int i=0; i<3; i++) {
            string ctx, rdata;
            pwencrypt(pw, msgs[i], ctx);
            REQUIRE(pwdecrypt(pw, ctx, rdata));
            REQUIRE( rdata == msgs[i] );
            REQUIRE_FALSE(pwdecrypt(pw+' ', ctx, rdata));
        }
    }

    PkCrypto pkobj;
    pkobj.initialize();
    SECTION("pk encrypt-decrypt") {
        byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
        string msgs[] = {
                "Hey here I am",
                "aaaaaaa",
                {_t1, _t1+6},
                ""
        };
        for(int i=0; i<3; i++) {
            string ctx, rdata;
            pkobj.pk_encrypt(msgs[i], ctx);
            pkobj.pk_decrypt(ctx, rdata);
            REQUIRE( rdata == msgs[i] );
        }
    }
    SECTION("pk load and dump key") {
        string msg = "Hello There";
        PkCrypto pkobj1;
        pkobj1.set_pk(pkobj.serialize_pk());
        PkCrypto pkobj2;
        pkobj2.set_sk(pkobj.serialize_sk());
        string ctx, rdata;
        pkobj1.pk_encrypt(msg, ctx);
        pkobj2.pk_decrypt(ctx, rdata);
        REQUIRE( rdata == msg );
    }

    SECTION("pk encrypt") {
        string ctx, rdata, msg="secret message";
        pkobj.pk_encrypt(msg, ctx);
        CHECK_THROWS(pkobj.pk_decrypt("adfasdf", rdata));
        CHECK(rdata != msg);
        CHECK(rdata.find(msg) == string::npos);
    }

    SECTION("pk_encrypt with google protobuf") {
        typtop::EncHeaderData ench;
        ench.set_pw("hello_rahul");
        for(int i=0; i<10; i++) {
            ench.add_freq(3);
            ench.add_last_used(13123);
        }
        ench.set_freq(2, 24);
        string ench_str, ench_ctx;
        pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
        pkobj.pk_decrypt(ench_ctx, ench_str);
        CHECK(ench_str == ench.SerializeAsString());

        typtop::EncHeaderData o_ench;
        o_ench.ParseFromString(ench_str);
        o_ench.add_freq(34);
        ench_ctx.clear(); ench_str.clear();
        pkobj.pk_encrypt(o_ench.SerializeAsString(), ench_ctx);
        pkobj.pk_decrypt(ench_ctx, ench_str);
        CHECK(ench_str == o_ench.SerializeAsString());
    }
    SECTION("Load and store pk and sk") {
        string sk = pkobj.serialize_sk();
        string pk = pkobj.serialize_pk();
        pkobj.set_sk(sk);
        CHECK(pkobj.serialize_pk() == pk);
        CHECK(pkobj.serialize_sk() == sk);
        pkobj.set_pk(pk);
        CHECK(pkobj.serialize_pk() == pk);
        CHECK_THROWS(pkobj.set_pk("adfafasdf"));
        CHECK_THROWS(pkobj.set_sk("adfafasdf"));
        PkCrypto pkobj1;
        string ctx;
        CHECK_THROWS(pkobj1.pk_encrypt(sk, ctx));
        CHECK_FALSE(pkobj1.can_decrypt());
        CHECK_FALSE(pkobj1.can_encrypt());
        pkobj1.set_sk(sk);
        CHECK(pkobj1.can_decrypt());
        CHECK(pkobj1.can_encrypt());
    }

    SECTION("Check a weird case") {
        string sk_str = b64decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBHYssFAMNGU5ZNpGrCBRsHmxTC_LGiQZEYhlQj6QZuLA");
        pkobj.set_sk(sk_str);
        string ench_ctx = b64decode("BHSzINxb56rx1M3np2KtMMgjfmxvwbuHgO1o1JfOJb5KxUaO6GWf4wM5E8iyYOzH7lMtUeJGGNvStBSKMJ9wpHIj38tvlzfA6awL3bgQh94558BtbKYVbW3CaKpCE8AuKlkM8yN2C-bMTzHP--Y-M8jZP-lGXH1Mozv-loRKh9tx0n9fKBZ-v5vO88rsNeU530iGGDMd4zctWqGioNrbKrc");
        string ench_str;
        pkobj.pk_decrypt(ench_ctx, ench_str);
        typtop::EncHeaderData ench;
        ench.ParseFromString(ench_str);
        cerr << ench.pw() << endl;
    }

    SECTION("TOO long pk_encrypt-decrypt") {
        string msg(200, 0);
        string ctx, rdata;
        pkobj.pk_encrypt(msg, ctx);
        pkobj.pk_decrypt(ctx, rdata);
        CHECK(b64encode(rdata) == b64encode(msg));
    }
}
