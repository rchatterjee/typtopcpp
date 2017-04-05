//
// Created by Rahul Chatterjee on 3/27/17.
//


#include <cassert>
#include "gcm.h"
using CryptoPP::GCM;

#include "pw_crypto.h"


/*
 * Simply computes sha256 hash of a vector of msgs.
 */
void hash256(const std::vector<string>& msgvec, SecByteBlock& digest ) {
    SHA256 hash;
    digest.resize(SHA256::DIGESTSIZE);
    for (auto it=msgvec.begin(); it != msgvec.end(); it++) {
        hash.Update((const byte*)it->data(), it->size());
        string _it_size = std::to_string(it->size());
        hash.Update((const byte*)(_it_size.c_str()), _it_size.size());
    }
    hash.Final(digest);
}

string hmac256(const SecByteBlock& key, const string& msg) {
    HMAC< SHA256 > hmac(key, key.size());
    string res;
    StringSource ss(msg, true, new HashFilter(hmac, new StringSink(res)));
    return res;
}

void PkCrypto::set_params() {
    _sk.AccessGroupParameters().SetPointCompression(true);
    _sk.AccessGroupParameters().SetEncodeAsOID(true);
    _pk.AccessGroupParameters().SetPointCompression(true);
    _pk.AccessGroupParameters().SetEncodeAsOID(true);
}

void PkCrypto::set_pk(const string& pk) {
    StringSource ss((const byte*)pk.data(), pk.size(), true);
    // _pk.BERDecode(ss);
    _pk.Load(ss);
    _pk.ThrowIfInvalid(PRNG, 3);
    _can_encrypt = true;
    set_params();
}
void PkCrypto::set_sk(const string& sk, bool gen_pk) {
    StringSource ss((const byte*)sk.data(), sk.size(), true);
    // _sk.BERDecode(ss);
    _sk.Load(ss);
    _sk.ThrowIfInvalid(PRNG, 3);
    if(gen_pk) {
        _sk.MakePublicKey(_pk);
        _can_encrypt = true;
    }
    _can_decrypt = true;
    set_params();
}
void PkCrypto::initialize() {
    _sk.Initialize(PRNG, CURVE);
    _sk.MakePublicKey(_pk);
    _can_encrypt = true;
    _can_decrypt = true;
}

const string PkCrypto::serialize_pk() {
    assert(_can_encrypt);
    string s;
    StringSink ss(s);
    set_params();
    //_pk.DEREncode(StringSink(s).Ref());
    _pk.Save(ss);
    return s;
}

const string PkCrypto::serialize_sk() {
    assert(_can_decrypt);
    string s;
    set_params();
    StringSink ss(s);
    // _sk.BEREncode(ss);
    _sk.Save(ss);
    return s;
}

void PkCrypto::pk_encrypt(const string &msg, string &ctx) const {
    ctx.clear();
    if(!_can_encrypt) throw("Cannot encrypt");
    auto e = myECIES::Encryptor(_pk);
    StringSource((const byte*)msg.data(), msg.size(), true,
                 new CryptoPP::PK_EncryptorFilter(PRNG, e, new StringSink(ctx)));
}

void PkCrypto::pk_decrypt(const string& ctx, string& msg) const {
    if(!_can_decrypt) throw("Cannot decrypt");
    msg.clear();
    auto d = myECIES::Decryptor(_sk);
    StringSource ss((const byte*)ctx.data(), ctx.size(), true,
                    new CryptoPP::PK_DecryptorFilter(PRNG, d, new StringSink(msg)));
}


void _slow_hash(const string &pw, const SecByteBlock& salt, SecByteBlock &key) {
    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
    const byte unused = 0;
    key.CleanNew(KEYSIZE_BYTES);
    pbkdf.DeriveKey(key, key.size(), unused,
                    (const byte*)pw.data(), pw.size(),
                    salt, salt.size(),
                    PBKDF_ITERATION_CNT);
}

/**
 * Generate key from the given pw and salt.
 * If the salt is not provided then it will generate a salt.
 */
bool harden_pw(const string pw, SecByteBlock& salt, SecByteBlock& key) {
    if (salt.empty()) {
        salt.resize(KEYSIZE_BYTES);
        PRNG.GenerateBlock(salt, KEYSIZE_BYTES);
    }
    if (key.empty()) {
        _slow_hash(pw, salt, key);
        return false;
    } else {
        SecByteBlock n_key;
        _slow_hash(pw, salt, n_key);
        return (n_key == key);
    }
}

bool pwencrypt(const string &pw, const string &msg, string& ctx) {
    bool ret = false;
    try {
        ctx.clear();
        SecByteBlock salt, key;
        harden_pw(pw, salt, key);
        string base_ctx;
        _encrypt(key, msg, "", base_ctx);
        // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
        StringSink ss(ctx);
        // ss.Put((const byte*)"SHA256", 6, true);
        ss.Put(salt, salt.size(), true);
        ss.Put((const byte*)base_ctx.data(), base_ctx.size(), true);
    } catch (CryptoPP::Exception& ex) {
        // cerr << ex.what() << endl;
        ret = false;
    }
    return ret;
}

bool pwdecrypt(const string &pw, const string &ctx, string &msg) {
    bool ret = false;
    SecByteBlock key;
    try {
        msg.clear();
        SecByteBlock salt((byte*)ctx.substr(0, KEYSIZE_BYTES).data(), KEYSIZE_BYTES);
        string base_ctx = ctx.substr(KEYSIZE_BYTES);
        harden_pw(pw, salt, key);
        _decrypt(key, base_ctx, "", msg);
        ret = true;
    } catch (CryptoPP::Exception& ex) {
        // cerr << ex.what() << endl;
        ret = false;
    }
    // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
    return ret;
}

/**
 *
 * @param key : Must of size AES::BLOCKSIZE
 * @param msg
 * @param extra_data
 * @param ctx : final output ciphertext is put in ctx.
 * AEAD scheme that encrypts msg and authenticate msg + extra_data. Return is pushed
 * ctx_format: <iv(AES::BLOCKSIZE)> + <msg_encryption> + <tag(MAC_SIZE_BYTES)>
 */
void _encrypt(const SecByteBlock &key, const string &msg, const string &extra_data, string& ctx) {
    GCM< AES, CryptoPP::GCM_2K_Tables>::Encryption encryptor;
    ctx.clear();
    assert( key.size() == AES::BLOCKSIZE );
    SecByteBlock iv(AES::BLOCKSIZE);
    PRNG.GenerateBlock(iv, AES::BLOCKSIZE);
    encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
    StringSink* ctx_sink = new StringSink(ctx);
    AuthenticatedEncryptionFilter ef(
            encryptor, ctx_sink, false, MAC_SIZE_BYTES
    );
    ctx_sink->Put(iv, iv.size(), true);

    // Authenticate the extra data first via AAD_CHANNEL.
    if (!extra_data.empty()) {
        ef.ChannelPut(AAD_CHANNEL, (const byte *) extra_data.data(), extra_data.size(), true);
        ef.ChannelMessageEnd(AAD_CHANNEL);
    }
    // Now encrypt and auth real data
    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*) msg.data(), msg.size(), true);
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);
}

void _decrypt(const SecByteBlock &key, const string &ctx, const string &extra_data, string& msg) {
    GCM< AES, CryptoPP::GCM_2K_Tables>::Decryption decryptor;
    string iv = ctx.substr(0, AES::BLOCKSIZE);
    string enc = ctx.substr(AES::BLOCKSIZE, ctx.length()-MAC_SIZE_BYTES-AES::BLOCKSIZE);
    string mac = ctx.substr(ctx.length()-MAC_SIZE_BYTES);
    // Sanity checks
//    cout << ctx.size() << " = " << iv.size() << " + "
//         << enc.size() << " + " << mac.size() << endl;
    assert( iv.size() == AES::BLOCKSIZE );
    assert( mac.size() == MAC_SIZE_BYTES );
    assert( ctx.size() == iv.size() + enc.size() + mac.size() );

    decryptor.SetKeyWithIV(key, key.size(), (const byte*)iv.data(), iv.size());

    AuthenticatedDecryptionFilter df(
            decryptor, new StringSink(msg),
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN | AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            MAC_SIZE_BYTES
    );
    // The order of the following calls are important
    df.ChannelPut( DEFAULT_CHANNEL, (const byte*)mac.data(), mac.size() );
    df.ChannelPut( AAD_CHANNEL,  (const byte*)extra_data.data(), extra_data.size() );
    df.ChannelPut( DEFAULT_CHANNEL, (const byte*)enc.data(), enc.size() );

    // If the object throws, it will most likely occur
    //   during ChannelMessageEnd()
    df.ChannelMessageEnd( AAD_CHANNEL );
    df.ChannelMessageEnd( DEFAULT_CHANNEL );

    // If the object does not throw, here's the only
    //  opportunity to check the data's integrity
    assert( df.GetLastResult() );

    // Remove data from channel
    // df.SetRetrievalChannel( DEFAULT_CHANNEL );
    // size_t n = (size_t)df.MaxRetrievable();
    // msg.clear(); msg.resize( n );
    // if( n > 0 ) { df.Get( (byte*)msg.data(), msg.size() ); }
}


