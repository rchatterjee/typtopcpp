//
// Created by Rahul Chatterjee on 3/28/17.
//

#include "typtop.h"
#include "cryptopp/files.h"
using CryptoPP::FileSource;
#include "pw_crypto.h"
#include "typo_util.hpp"

// Password length for random entries
#define DEFAULT_PW_LENGTH 16

TypTop::TypTop(const string& _db_fname, const string& real_pw) : db_fname(_db_fname) {
    if (!db.ParseFromIstream(new std::fstream(db_fname, ios::in|ios::binary))) {
        std::cerr << "Something went wrong or the file is empty" << endl;
        assert(!real_pw.empty());
        initialize(db_fname, real_pw);
    }
}

TypTop::~TypTop() {
    string db_bak = db_fname + ".bak";
    std::fstream of(db_bak, ios::out|ios::binary);
    db.SerializeToOstream(&of);
    rename(db_bak.c_str(), db_fname.c_str());
}

string get_homedir(void)
{
#ifdef DEBUG
    return "./";
#endif
    char homedir[1024];
#ifdef _WIN32
    snprintf(homedir, MAX_PATH, "%s%s", getenv("HOMEDRIVE"), getenv("HOMEPATH"));
#else
    snprintf(homedir, 1024, "%s", getenv("HOME"));
#endif
    return strdup(homedir);
}

string get_uniq_id() {
    string homdir(get_homedir());
    string UNIQ_ID_FILENAME = homdir + "/.typtop.uniq.id";
    std::fstream f(UNIQ_ID_FILENAME, ios::in);
    string id;
    if (f.good() && (f >> id) && id.size()>=8) {
        cout << "Install ID.fromFile: "<< id << endl;
        return id;
    } else { // generate and store
        SecByteBlock b(8);
        f.close();
        PRNG.GenerateBlock(b, 8);
        id = b64encode(b);
        std::fstream of(UNIQ_ID_FILENAME, ios::out);
        of << id;
        of.close();

        cout << "Install ID: "<< id << endl;
    }
    return id;
}

void TypTop::fill_waitlist_w_garbage() {
    for(int i=0; i<W_size; i++) {
        SecByteBlock b(DEFAULT_PW_LENGTH);
        PRNG.GenerateBlock(b, DEFAULT_PW_LENGTH);
        string ctx;
        pkobj.pk_encrypt(string((char*)b.data(), b.size()), ctx);
        db.add_w(ctx);
    }
}

void TypTop::initialize(const string& _db_fname, const string& real_pw) {
    ConfigHeader* ch = db.mutable_ch();
    Header* h = db.mutable_h();
    EncHeaderData* ench = h->mutable_enc_header();

    ch->set_install_id(get_uniq_id());
    pkobj.initialize();

    ch->set_public_key(pkobj.serialize_pk());
    SecByteBlock global_salt(AES::BLOCKSIZE);
    PRNG.GenerateBlock(global_salt, AES::BLOCKSIZE);  // random element
    ch->set_global_salt((const char*)global_salt.data(), global_salt.size());

    string sk_str = pkobj.serialize_sk();

    ench->set_pw(real_pw);
    std::vector<string>T_cache(T_size);
    get_typos(real_pw, T_cache);

    for(int i=0; i<T_size; i++) {
        if (T_cache[i].empty()) { // generate random
            SecByteBlock b(DEFAULT_PW_LENGTH);
            PRNG.GenerateBlock(b, DEFAULT_PW_LENGTH);
            T_cache[i] = (char *)b.data();
        } else {
            insert_into_log(T_cache[i], true, -1); // sets L
        }
        string sk_ctx;
        pwencrypt(T_cache[i], sk_str, sk_ctx);
        ench->add_freq(0);
        db.add_t(sk_ctx);  // setting T
    }
    fill_waitlist_w_garbage();   // sets W
    cout << "db: " << db.DebugString() << endl;
    assert(db.IsInitialized());
}

void TypTop::insert_into_log(const string& pw, bool in_cache, int ts) {
    Log* l = db.add_l();
    l->set_in_cache(in_cache);
    l->set_istop5fixable(top5fixable(real_pw, pw));
    l->set_edit_dist(edit_distance(pw, real_pw));
    l->set_rel_entropy(-99);  // TODO: Find a way toestimate this
    static SecByteBlock g_salt((const byte *)db.ch().global_salt().data(), db.ch().global_salt().size());
    l->set_tid(compute_id(g_salt, pw));
    l->set_ts(time(NULL));
    l->set_localtime(localtime());
}
