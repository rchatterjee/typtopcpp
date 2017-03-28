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

#include <string>
using std::string;

#include "cryptopp/cryptlib.h"
using CryptoPP::lword;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::Exception;

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

void DeriveKeyAndIV(const string& master, const string& salt,
                    unsigned int iterations,
                    SecByteBlock& ekey, unsigned int eksize,
                    SecByteBlock& iv, unsigned int vsize,
                    SecByteBlock& akey, unsigned int aksize);

void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey);


#endif //TYPTOP_C_PW_CRYPTO_H
