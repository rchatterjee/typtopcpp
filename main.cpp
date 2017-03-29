#include <iostream>
#include <cassert>
#include "pw_crypto.h"
#include "typtop.h"

int main(int argc, char *argv[]) {
    std::cout << "Hello, World!" << std::endl;
    (void) argc;
    (void) argv;

    string password = "Super secret password";
    if (argc >= 2 && argv[1] != NULL)
        password = string(argv[1]);

    string message = "Now is the time for all good men to come to the aide of their country";
    if (argc >= 3 && argv[2] != NULL)
        message = string(argv[2]);

//    try {
    string m = "Hello world";
    SecByteBlock digest1, digest2, salt;
    harden_pw(m, salt, digest1);
    harden_pw(m, salt, digest2);
    assert(digest1 == digest2);

    string digest_str;
    debug_print(digest1.data(), digest1.size(), "Digest");
    digest1.resize(AES::BLOCKSIZE);

    PkCrypto pkobj;
    pkobj.initialize();
    string pk_str = pkobj.serialize_pk();
    string sk_str = pkobj.serialize_sk();
    cout << b64encode(pk_str) << endl << pk_str.size() << endl;
    cout << b64encode(sk_str) << endl << sk_str.size() << endl;

    cout << "stopped here" << endl;
    string ctx, rdata;
    pkobj.pk_encrypt(m, ctx);
    print_raw_byte((const byte *) ctx.data(), ctx.size());
    pkobj.pk_decrypt(ctx, rdata);
    assert(rdata == m);

    /**************************************************************/
    string fname = "./tmp_db";
    TypTop tp(fname, "hello_pass");
    


//    }
//    catch(CryptoPP::Exception& ex)
//    {
//        cerr << ex.what() << endl;
//    }

    return 0;
}