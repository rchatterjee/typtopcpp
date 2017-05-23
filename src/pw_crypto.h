//
// Created by Rahul Chatterjee on 3/27/17.
//

#ifndef TYPTOP_C_PW_CRYPTO_H
#define TYPTOP_C_PW_CRYPTO_H

#include <iostream>
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#include <iomanip>
#include <string>
#include <cassert>

using std::string;

#include "ecp.h"
using CryptoPP::ECP;

#include "eccrypto.h"
using CryptoPP::ECDH;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "asn.h"
#include "oids.h"
using CryptoPP::OID;
using CryptoPP::ASN1::secp256r1;

#include "cryptlib.h"
using CryptoPP::lword;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::Exception;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::AAD_CHANNEL;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;


#include "secblock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::SecBlock;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::HashFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "files.h"
using CryptoPP::FileSink;

#include "sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "hmac.h"
using CryptoPP::HMAC;

#include "base64.h"
using CryptoPP::Base64URLEncoder;
using CryptoPP::Base64URLDecoder;

typedef unsigned long ulong;

static const uint8_t KEYSIZE_BYTES = AES::DEFAULT_KEYLENGTH;  // key size 16 bytes
static const uint32_t PBKDF_ITERATION_CNT = 20000;   // number of hash iterations
static const uint32_t MAC_SIZE_BYTES = 16; // size of tag
static AutoSeededRandomPool PRNG;  // instantiate only one class
static const OID CURVE = secp256r1();

typedef CryptoPP::ECIES<ECP, CryptoPP::IncompatibleCofactorMultiplication, true> myECIES;


/* Hashing related functions */
void hash256(const std::vector<string>&, SecByteBlock&);
bool harden_pw(const string pw, SecByteBlock& salt, SecByteBlock& key);
void _slow_hash(const string& pw, const SecByteBlock& salt,
                SecByteBlock& key);

/* Symmetric key functions */
bool pwencrypt(const string& pw, const string& msg, string& ctx);
bool pwdecrypt(const string& pw, const string& ctx, string& msg);

void _encrypt(const SecByteBlock& key, const string& msg, const string& extra_data, string& ctx);
void _decrypt(const SecByteBlock& key, const string& ctx, const string& extra_data, string& msg);

/* Public Key Functions */
class PkCrypto {
private:
    myECIES::PublicKey _pk;
    myECIES::PrivateKey _sk;
    bool _can_decrypt = false;
    bool _can_encrypt = false;
public:
    // PkCrypto();
    void set_pk(const string& pk);
    void set_sk(const string& sk, bool gen_pk=false);
    void initialize();
    const string serialize_pk();
    const string serialize_sk();
    inline bool can_decrypt() const { return _can_decrypt; }
    inline bool can_encrypt() const { return _can_encrypt; }

    void pk_encrypt(const string &msg, string &ctx) const;
    void pk_decrypt(const string& ctx, string& msg) const;

protected:
    void set_params();
};

void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey);

/* Utility Functions */
inline void b64encode(const byte* raw_bytes, ulong len, string& str) {
    StringSource ss( raw_bytes, len, true, new Base64URLEncoder(new StringSink(str), true));
    // StringSource ss( raw_bytes, len, true, new HexEncoder(new StringSink(str)));
}
inline void b64decode(const string& str, string& byte_str){
    StringSource ss(str, true, new Base64URLDecoder(new StringSink(byte_str)));
}
inline string b64encode(const SecByteBlock& raw_bytes) {
    string s;
    b64encode(raw_bytes.data(), raw_bytes.size(), s);
    return s;
}

// Some extra useful functions
string hmac256(const SecByteBlock& key, const string& msg);

// id size is only 8
inline uint32_t compute_id(const SecByteBlock& key, const string& msg) {
    // cheap way to convert byte array to int, susceptible to machine endianness, but fine for me
    return *(uint32_t*)hmac256(key, msg).substr(0, 4).data();
}

inline string b64encode(const string& in){ string out; b64encode((const byte*)in.data(), in.size(), out); return out; }
inline string b64decode(const string& in) { string out; b64decode(in, out); return out; }

/*
 string bytes_to_str(const SecByteBlock& b) {
    return string((char*)b.data(), b.size());
}*/

inline std::ostream& operator<< (std::ostream& os, SecByteBlock const& value){
    string s;
    StringSource(value.data(), value.size(), true, new HexEncoder(new StringSink(s)));
    os << s;
    return os;
}

inline void debug_print(byte* m, size_t len, string name="") {
#ifdef DEBUG
    string key_str;
    b64encode(m, len, key_str);
    cout << name << " -> " << key_str << endl;
#endif
}

#endif //TYPTOP_C_PW_CRYPTO_H
