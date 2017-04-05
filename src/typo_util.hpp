//
// Created by Rahul Chatterjee on 3/28/17.
//

#ifndef TYPTOP_C_TYPO_UTIL_HPP
#define TYPTOP_C_TYPO_UTIL_HPP

#include <iostream>
#include <vector>
#include <set>
#include <algorithm>
#include <numeric>
#include "zxcvbn.h"
#include "plog/Log.h"

using namespace std;

// TODO: Move to typtopconfig.h, or db.proto
#define EDIST_CUTOFF 1
#define ENTROPY_CUTOFF 3

inline int swapcase(int chr) {
    return islower(chr) ? toupper(chr) : tolower(chr);
}

inline string swapcase(const string& str) {
    string ret(str.size(), 0);
    std::transform(str.begin(), str.end(), ret.begin(),
                   static_cast<int(*)(int)>(swapcase));
    return ret;
}

inline string toupper(const string& str) {
    string ret(str.size(), 0);
    std::transform(str.begin(), str.end(), ret.begin(),
                   static_cast<int(*)(int)>(::toupper));
    return ret;
}

inline string tolower(const string& str) {
    string ret(str.size(), 0);
    transform(str.begin(), str.end(), ret.begin(),
              static_cast<int(*)(int)>(::tolower));
    return ret;
}

inline char change_shift(char c) {
    static const char* non_shift_syms = "`1234567890-=[]\\;',./";
    static const char* shifted_syms = "~!@#$%^&*()_+{}|:\"<>?";
    static size_t _len_syms = strlen(non_shift_syms);
    for(size_t i=0; i<_len_syms; i++) {
        if (non_shift_syms[i] == c) return shifted_syms[i];
        else if (shifted_syms[i] == c) return non_shift_syms[i];
    }
    return c;
}

inline bool top5fixable(const string& real_pw, const string& pw) {
    return (swapcase(pw) == real_pw ||  // caps-lock key error
            (char)swapcase(pw[0]) + pw.substr(1) == real_pw ||  //shift key error
            pw.substr(0, pw.size()-1) == real_pw ||
            pw.substr(1) == real_pw ||
            pw.substr(0, pw.size()-1) + change_shift(pw[pw.size()-1]) == real_pw
    );
}

inline void get_typos(const string& pw, vector<string>& ret) {
    if (pw.size()<2) {
        return;
    }
    vector<string> typos = {
            swapcase(pw.c_str()),
            (char)swapcase(pw[0]) + pw.substr(1),
            pw.substr(0, pw.size()-1),
            pw.substr(1),
            (pw + "1"),
            (pw + "`"),
            toupper(pw),
            tolower(pw),
    };
    set<string> typo_set(typos.begin(), typos.end());
    size_t i=0;
    for(auto it = typo_set.begin(); it != typo_set.end(); it++) {
        if (it->compare(pw) == 0) continue;
        ret[i++] = *it;
        if (i>=ret.size()) break;
    }
    typo_set.clear(); typos.clear();
}



/**
 * Sort based on indices.
 * From http://stackoverflow.com/a/12399290/1792013
 */
template <typename T>
inline vector<size_t> sort_indexes(const vector<T> &v) {

    // initialize original index locations
    vector<size_t> idx(v.size());
    iota(idx.begin(), idx.end(), 0);

    // sort indexes based on comparing values in v
    sort(idx.begin(), idx.end(),
         [&v](size_t i1, size_t i2) {return v[i1] < v[i2];});

    return idx;
}

inline int64_t now() {
    return time(NULL);
}

inline string localtime() {
    time_t rawtime;
    time (&rawtime);
    return asctime(localtime (&rawtime));
}

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

inline int _vanilla_edit_distance(const string& s1, const string& s2) {
    unsigned int x, y;
    size_t s1len = s1.size(), s2len=s2.size();
    unsigned int matrix[s2len+1][s1len+1];
    matrix[0][0] = 0;
    for (x = 1; x <= s2len; x++)
        matrix[x][0] = matrix[x-1][0] + 1;
    for (y = 1; y <= s1len; y++)
        matrix[0][y] = matrix[0][y-1] + 1;
    for (x = 1; x <= s2len; x++)
        for (y = 1; y <= s1len; y++) {
            matrix[x][y] = MIN3(
                    matrix[x - 1][y] + 1,
                    matrix[x][y - 1] + 1,
                    matrix[x - 1][y - 1] + (s1[y - 1] == s2[x - 1] ? 0 : 1)
            );
            if (x>=2 && y>=2) {
                int transpose_cost = (s1[y-2] == s2[x-1] && s1[y-1] == s2[x-2]) ? 1 : 2;
                matrix[x][y] = std::min(matrix[x][y], matrix[x-2][y-2] + transpose_cost);
            }
        }
    return(matrix[s2len][s1len]);
}

inline int edit_distance(const string& s1, const string&s2){
    // TODO use word2keypress distance
    int edist = _vanilla_edit_distance(s1, s2);
    if(edist>1){ // check for swaped cases
        if(swapcase(s1) == s2) return 1;
    }
    return edist;
}

inline string get_homedir(void) {
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

/**
 * Compares the f_o (old f) and f_n (new f) to
 * decide whether or not the old should be evicted
 * Right now the probability of eviction is f_n/(f_n+f_o)
 * --> It prefers to keep (returns false more often)
 */
inline bool win(int f_o, int f_n) {
    if (f_n <= 0 || f_o >= INT_MAX) return false;
    if (f_o <= 0 || f_n >= INT_MAX) return true;
    if (f_o > INT_MAX-f_n) return (f_n>=f_o); // never change real passwords
    int d = f_o + f_n;
    if (d<=0) throw;
    return ((int)PRNG.GenerateWord32(0, (uint32_t)d) < f_n);
}

/**
 * @return install id. Currently the install_id is just a file in the home
 * directory of the active user.
 */
inline string get_install_id() {
    string homdir(get_homedir());
    string UNIQ_ID_FILENAME = homdir + "/.typtop.uniq.id";
    std::fstream f(UNIQ_ID_FILENAME, ios::in);
    string id;
    if (f.good() && (f >> id) && id.size()>=8) {
        cerr << "Install ID.fromFile: "<< id << endl;
        return id;
    } else { // generate and store
        f.close();
        SecByteBlock b(8);
        PRNG.GenerateBlock(b.data(), 8);
        id = b64encode(b);
        std::fstream of(UNIQ_ID_FILENAME, ios::out);
        of << id;
        of.close();

        cerr << "Install ID.Regenerated: "<< id << endl;
    }
    return id;
}

inline float entropy(const string& pw) {
    double ent = -99.0;
    try {
        ent = ZxcvbnMatch(pw.c_str(), NULL, NULL);
    } catch (exception &ex){
        LOG_ERROR << ex.what();
    }
    return ent;
}

/**
 * Policies:
 * 1. the edit-distance with the pw should be less than EDIST_CUTOFF
 * 2. the size of the typo should not be <= 6 char
 * 3. the entropy degradation should not be less than 3 bits
 * 4. minimum entropy of the typo should be at least 10 bits
 * @param pw: real password
 * @param typo: Whether the typo can be allowed to get into the cache
 */
inline bool meets_typo_policy(const string& pw, const string& typo) {
    // TODO: Add entropy requirements
#ifdef ENTROYP_CUTOFF
    double entropy_pw = entropy(pw);
    double entropy_typo = entropy(pw);
    if (entropy_typo < entropy_pw - ENTROPY_CUTOFF) return false;
#endif
    // if (entropy_typo < 10) return false;  // ignore it for now
    return typo.size() > 6 && edit_distance(pw, typo) <= EDIST_CUTOFF;
}

#endif //TYPTOP_C_TYPO_UTIL_HPP
