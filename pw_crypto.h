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

static const uint8_t KEYSIZE_BYTES = AES::BLOCKSIZE;  // key size 16 bytes
static const uint32_t PBKDF_ITERATION_CNT = 1000;
static const uint32_t MAC_SIZE_BYTES = 16; // size of tag
static AutoSeededRandomPool PRNG;  // instantiate only one class

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
void create_key_pair(SecByteBlock& priv_key, SecByteBlock& pub_key);
void pk_encrypt(SecByteBlock& pub_key, string& msg);
void pk_decrypt(SecByteBlock& priv_key, string& msg);



void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey);

/* Utility Functions */
void b64encode(const byte* raw_bytes, ulong len, string& str);
void b64decode(const string& str, string& byte_str);
inline string b64encode(const SecByteBlock& raw_bytes) {
    string s;
    b64encode(raw_bytes.data(), raw_bytes.size(), s);
    return s;
}
// Some extra useful functions
string hmac256(const SecByteBlock& key, const string msg);
string b64encode(string);
string b64decode(string);
SecByteBlock get_rand_bytes(const uint32_t len);

inline void print_raw_byte(const byte* m, const ulong len) {
    for (ulong i = 0; i < len; ++i)
        cout << std::hex << std::setfill('0') << std::setw(2) << m[i] << " ";
    cout << endl;
}
inline void debug_print(byte* m, size_t len, string name="") {
#ifdef DEBUG
    string key_str;
    b64encode(m, len, key_str);
    cout << name << " -> " << key_str << endl;
#endif
}

#endif //TYPTOP_C_PW_CRYPTO_H
