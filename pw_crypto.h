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
using std::string;

#include "cryptopp/ecp.h"
using CryptoPP::ECP;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDH;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/asn.h"
#include "cryptopp/oids.h"
using CryptoPP::OID;
using CryptoPP::ASN1::secp256r1;

#include "cryptopp/cryptlib.h"
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


#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::SecBlock;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::HashFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSink;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

#include "cryptopp/base64.h"
using CryptoPP::Base64URLEncoder;
using CryptoPP::Base64URLDecoder;

typedef unsigned long ulong;

static const uint8_t KEYSIZE_BYTES = AES::BLOCKSIZE;  // key size 16 bytes
static const uint32_t PBKDF_ITERATION_CNT = 1000;
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
void pwencrypt(const string& pw, const string& msg, string& ctx);
void pwdecrypt(const string& pw, const string& ctx, string& msg);

void _encrypt(const SecByteBlock& key, const string& msg, const string& extra_data, string& ctx);
void _decrypt(const SecByteBlock& key, const string& ctx, const string& extra_data, string& msg);

/* Public Key Functions */
class PkCrypto {
private:
    myECIES::Decryptor d;
    myECIES::Encryptor e;
    bool _can_decrypt = false;
public:
    // PkCrypto(string pk="", string sk="", bool initialize=false);
    void set_pk(const string& pk);
    void set_sk(const string& sk);
    void initialize();
    string serialize_pk();
    string serialize_sk();
    inline bool can_decrypt() const { return _can_decrypt; }

    inline void pk_encrypt(const string &msg, string &ctx) {
        StringSource(msg, true, new CryptoPP::PK_EncryptorFilter(PRNG, e, new StringSink(ctx)));
    }

    inline void pk_decrypt(const string& ctx, string& msg) {
        StringSource(ctx, true, new CryptoPP::PK_DecryptorFilter(PRNG, d, new StringSink(msg)));
    }
};

CryptoPP::DL_PrivateKey_EC<ECP> generate_privkey();
void pk_encrypt(const PublicKey& pub_key, const string& msg, string& ctx);
void pk_decrypt(const PrivateKey& priv_key, const string& ctx, string& msg);


void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey);

/* Utility Functions */
inline void b64encode(const byte* raw_bytes, ulong len, string& str) {
    StringSource ss( raw_bytes, len, true, new Base64URLEncoder(new StringSink(str), true));
    // StringSource ss( raw_bytes, len, true, new HexEncoder(new StringSink(str)));
    cout << str.size() << endl;
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

SecByteBlock get_rand_bytes(const uint32_t len);

inline void print_raw_byte(const byte* m, const ulong len) {
    string s;
    StringSource(m, len, true, new HexEncoder(new StringSink(s)));
    cout << s << endl;
}

inline void debug_print(byte* m, size_t len, string name="") {
#ifdef DEBUG
    string key_str;
    b64encode(m, len, key_str);
    cout << name << " -> " << key_str << endl;
#endif
}

#endif //TYPTOP_C_PW_CRYPTO_H
