#include <iostream>
#include <cassert>
#include "pw_crypto.h"

int main(int argc, char* argv[]) {
    std::cout << "Hello, World!" << std::endl;
    (void)argc; (void)argv;

    string password = "Super secret password";
    if(argc >= 2 && argv[1] != NULL)
        password = string(argv[1]);

    string message = "Now is the time for all good men to come to the aide of their country";
    if(argc >= 3 && argv[2] != NULL)
        message = string(argv[2]);

    try {
        string m = "Hello world";
        SecByteBlock digest1, digest2, salt;
        harden_pw(m, salt, digest1);
        harden_pw(m, salt, digest2);
        assert( digest1 == digest2 );

        string digest_str;
        debug_print(digest1.data(), digest1.size(), "Digest");

        string ctx, rdata;
        digest1.resize(AES::BLOCKSIZE);
//        _encrypt(digest, m, "", ctx);
//        _decrypt(digest, ctx, "", rdata);
        pwencrypt(m, m, ctx);
        pwdecrypt(m, ctx, rdata);
        assert( rdata == m );
    }
    catch(CryptoPP::Exception& ex)
    {
        cerr << ex.what() << endl;
    }

    return 0;
}