#include <iostream>
#include <cassert>
#include "pw_crypto.h"
#include "typtop.h"
#include "zxcvbn.h"

int main(int argc, char *argv[]) {
//    try {
    /*
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
    cout << ctx << endl;
    pkobj.pk_decrypt(ctx, rdata);
    assert(rdata == m);
    */
    /**************************************************************/
    Logs logs;
    logs.ParseFromString(b64decode(argv[1]));
    logs.PrintDebugString();

//    TypTop tp(fname);
//    cout << "Trying 0: " << tp.check(pws[0], true) << endl;
//    cout << "Trying 1: " << tp.check(pws[1], false) << endl;
//    }
//    catch(CryptoPP::Exception& ex)
//    {
//        cerr << ex.what() << endl;
//    }

    return 0;
}