//
// Created by Rahul Chatterjee on 3/27/17.
//

#include "pw_crypto.h"

void DeriveKeyAndIV(const string& master, const string& salt,
                    unsigned int iterations,
                    SecByteBlock& ekey, unsigned int eksize,
                    SecByteBlock& iv, unsigned int vsize,
                    SecByteBlock& akey, unsigned int aksize)
{

    SecByteBlock tb, ts(SHA512::DIGESTSIZE), tm(SHA512::DIGESTSIZE);

    // Temporary salt, stretch size.
    SHA512 hash;
    hash.CalculateDigest(ts, (const byte*)salt.data(), salt.size());

    static const string s1 = "master key";
    tb = SecByteBlock((const byte*)master.data(), master.size()) + SecByteBlock((const byte*)s1.data(), s1.size());

    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
    const byte unused = 0;
    pbkdf.DeriveKey(tm, tm.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);

    static const string s2 = "encryption key";
    ekey.resize(eksize);
    tb = tm + SecByteBlock((const byte*)s2.data(), s2.size());
    pbkdf.DeriveKey(ekey, ekey.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);

    static const string s3 = "initialization vector";
    iv.resize(vsize);
    tb = tm + SecByteBlock((const byte*)s3.data(), s3.size());
    pbkdf.DeriveKey(iv, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);

    static const string s4 = "authentication key";
    akey.resize(aksize);
    tb = tm + SecByteBlock((const byte*)s4.data(), s4.size());
    pbkdf.DeriveKey(akey, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);
}

void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey)
{
    // Print them
    HexEncoder encoder(new FileSink(cout));

    cout << "AES key: ";
    encoder.Put(ekey.data(), ekey.size());
    encoder.MessageEnd(); cout << endl;

    cout << "AES IV: ";
    encoder.Put(iv.data(), iv.size());
    encoder.MessageEnd(); cout << endl;

    cout << "HMAC key: ";
    encoder.Put(akey.data(), akey.size());
    encoder.MessageEnd(); cout << endl;
}