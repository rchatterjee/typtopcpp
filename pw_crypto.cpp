//
// Created by Rahul Chatterjee on 3/27/17.
//


#include <cassert>
#include "cryptopp/gcm.h"
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

string hmac256(const SecByteBlock& key, const string msg) {
    HMAC< SHA256 > hmac(key, key.size());
    string res;
    StringSource ss(
            msg, true,
            new HashFilter(hmac, new StringSink(res)) // HashFilter
    ); // StringSource
    return res;
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

void b64encode(const byte *raw_bytes, ulong len, string& str) {
    StringSource ss(
            raw_bytes, len, true,
            new Base64URLEncoder(
                    new StringSink(str)
            ) // Base64URLEncoder
    ); // StringSource
}

void b64decode(const string& str, string& byte_str){
    StringSource ss(str, true,
                    new Base64URLDecoder(
                            new StringSink(byte_str)
                    ) // Base64URLDecoder
    ); // StringSource
}

string b64encode(string in) {
    string out;
    b64encode((const byte*)in.data(), in.size(), out);
    return out;
}
string b64decode(string in) {
    string out;
    b64decode(in, out);
    return out;
}


void create_key_pair(SecByteBlock& priv_key, SecByteBlock& pub_key) {
    OID CURVE = secp256r1();
    AutoSeededRandomPool prng;
    ECDH<ECP>::Domain ecdh(CURVE);

    priv_key.resize(ecdh.PrivateKeyLength());
    pub_key.resize(ecdh.PublicKeyLength());
    ecdh.GenerateKeyPair(prng, priv_key, pub_key);
}

SecByteBlock get_rand_bytes(const uint32_t len) {
    SecByteBlock salt(len);
    PRNG.GenerateBlock(salt, len);
    return salt;
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

/*
 * Generate key from the given pw and salt.
 * If the salt is not provided then it will generate a salt.
 */
bool harden_pw(const string pw, SecByteBlock& salt, SecByteBlock& key) {
    if (salt.empty()) {
        salt = get_rand_bytes(KEYSIZE_BYTES);
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

void pwencrypt(const string &pw, const string &msg, string& ctx) {
    SecByteBlock salt;
    SecByteBlock key;
    harden_pw(pw, salt, key);

    debug_print(key.data(), key.size(), "pwencrypt.Key");
    debug_print(salt.data(), salt.size(), "pwencrypt.Salt");

    string base_ctx;
    _encrypt(key, msg, "", base_ctx);
    // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
    StringSink ss(ctx);
    // ss.Put((const byte*)"SHA256", 6, true);
    ss.Put(salt, salt.size(), true);
    ss.Put((const byte*)base_ctx.data(), base_ctx.size(), true);
    key.CleanNew(0); // delete the key
}

void pwdecrypt(const string &pw, const string &ctx, string &msg) {
    SecByteBlock salt((byte*)ctx.substr(0, KEYSIZE_BYTES).data(), KEYSIZE_BYTES);
    string base_ctx = ctx.substr(KEYSIZE_BYTES);
    SecByteBlock key;
    harden_pw(pw, salt, key);

    debug_print(key.data(), key.size(), "pwdecrypt.Key");
    debug_print(salt.data(), salt.size(), "pwdecrypt.Salt");

    _decrypt(key, base_ctx, "", msg);
    // TODO:  <hash_algo>.<iteration_cnt>.<salt>.<ctx>
    key.CleanNew(0); // delete the key
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
    assert( key.size() == AES::BLOCKSIZE );
    SecByteBlock iv(AES::BLOCKSIZE);
    PRNG.GenerateBlock(iv, AES::BLOCKSIZE);
    encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
    StringSink* ctx_sink = new StringSink(ctx);
    AuthenticatedEncryptionFilter ef(
            encryptor, ctx_sink, false, MAC_SIZE_BYTES
    );
    ctx_sink->Put(iv, iv.size(), true);
#ifdef DEBUG
    string key_str;
    b64encode(key.data(), key.size(), key_str);
    cout << key_str << endl;
#endif
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
    cout << ctx.size() << " = " << iv.size() << " + "
         << enc.size() << " + " << mac.size() << endl;
    assert( iv.size() == AES::BLOCKSIZE );
    assert( mac.size() == MAC_SIZE_BYTES );
    assert( ctx.size() == iv.size() + enc.size() + mac.size() );

    decryptor.SetKeyWithIV(key, key.size(), (const byte*)iv.data(), iv.size());

    AuthenticatedDecryptionFilter df(
            decryptor, NULL,
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
    assert( true == df.GetLastResult() );

    // Remove data from channel
    df.SetRetrievalChannel( DEFAULT_CHANNEL );
    size_t n = (size_t)df.MaxRetrievable();
    msg.resize( n );

    if( n > 0 ) { df.Get( (byte*)msg.data(), n ); }
    assert( msg.empty() != true );
}
