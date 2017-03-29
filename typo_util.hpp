//
// Created by Rahul Chatterjee on 3/28/17.
//

#ifndef TYPTOP_C_TYPO_UTIL_HPP
#define TYPTOP_C_TYPO_UTIL_HPP

#include <iostream>
#include <vector>
#include <set>
#include <algorithm>

using namespace std;

int swapcase(int chr) {
    return islower(chr) ? toupper(chr) : tolower(chr);
}

string swapcase(const string& str) {
    string ret(str.size(), 0);
    std::transform(str.begin(), str.end(), ret.begin(),
                   static_cast<int(*)(int)>(swapcase));
    return ret;
}

string toupper(const string& str) {
    string ret(str.size(), 0);
    std::transform(str.begin(), str.end(), ret.begin(),
                   static_cast<int(*)(int)>(::toupper));
    return ret;
}

string tolower(const string& str) {
    string ret(str.size(), 0);
    transform(str.begin(), str.end(), ret.begin(),
              static_cast<int(*)(int)>(::tolower));
    return ret;
}

char change_shift(char c) {
    static const char* non_shift_syms = "`1234567890-=[]\\;',./";
    static const char* shifted_syms = "~!@#$%^&*()_+{}|:\"<>?";
    static size_t _len_syms = strlen(non_shift_syms);
    for(int i=0; i<_len_syms; i++) {
        if (non_shift_syms[i] == c) return shifted_syms[i];
        else if (shifted_syms[i] == c) return non_shift_syms[i];
    }
    return c;
}
bool top5fixable(const string& real_pw, const string& pw) {
    return (swapcase(pw) == real_pw ||  // caps-lock key error
            (char)swapcase(pw[0]) + pw.substr(1) == real_pw ||  //shift key error
            pw.substr(0, pw.size()-1) == real_pw ||
            pw.substr(1) == real_pw ||
            pw.substr(0, pw.size()-1) + change_shift(pw[pw.size()-1]) == real_pw
    );
}

void get_typos(const string& pw, vector<string>& ret) {
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
    int i=0;
    for(auto it = typo_set.begin(); it != typo_set.end(); it++) {
        if (it->compare(pw) == 0) continue;
        ret[i++] = *it;
        if (i>=ret.size()) break;
    }
    typo_set.clear(); typos.clear();
}


string localtime() {
    time_t rawtime;
    time (&rawtime);
    return asctime(localtime (&rawtime));
}

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

int edit_distance(const string& s1, const string& s2) {
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
                int transpose_cost = (s1[y-2] == s2[x-1] && s1[y-1] == s2[x-2]) ? 0 : 2;
                matrix[x][y] = std::min(matrix[x][y], matrix[x-2][y-2] + transpose_cost);
            }
        }
    return(matrix[s2len][s1len]);
}

#endif //TYPTOP_C_TYPO_UTIL_HPP
