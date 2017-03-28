//
// Created by rahul on 3/28/17.
//

#include "pw_crypto.h"
#include "catch.hpp"

using std::vector;

TEST_CASE("finv(f(m)) == m", "[base64]") {
    SECTION ("b64 encode decode") {
        vector<SecByteBlock> raw_bytes(3);
        byte _t1[] = {0x12, 0x12, 0x45, 0xf2, 0x34};
        raw_bytes[0] = SecByteBlock((const byte *) "aaa13", 5);
        raw_bytes[1] = SecByteBlock((const byte *) "", 0);
        raw_bytes[2] = SecByteBlock(_t1, 5);

        for (size_t i = 0; i < raw_bytes.size(); i++) {
            string _t_encoded, _t_byte_str;
            string res = b64decode(b64encode(raw_bytes[i]));
            int b = raw_bytes[i] == res.data();
            if (b != 0) {
                cout << "i: " << i << endl;
                cout << res << endl;
                cout << raw_bytes[i].data() << endl;
            }
            REQUIRE(b == 0);
        }
    }
    SECTION("pwnecrypt decrypt") {
        string pw = "Super secret pw";
        string msgs[] = {
                "Hey here I am",
                {23, 56, 123, 46, 129},
                "aaaaaaa"
        };
        for(int i=0; i<3; i++) {
            string ctx, rdata;
            pwencrypt(pw, msgs[i], ctx);
            pwdecrypt(pw, ctx, rdata);
            REQUIRE( rdata == msgs[i] );
        }
    }
};
