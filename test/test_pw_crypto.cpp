//
// Created by rahul on 3/28/17.
//

#include "src/pw_crypto.h"
#include "catch.hpp"

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
            CHECK( b == 0 );
        }
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
            pwdecrypt(pw, ctx, rdata);
            REQUIRE( rdata == msgs[i] );
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
}
