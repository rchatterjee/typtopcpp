//
// Created by rahul on 4/2/17.
//

#include "typtop.h"

vector<string> find_what_in(const TypTop& tp, string const &real_pw) {
    vector<string> typos(10), present; // try more once we have a good function
    get_typos(real_pw, typos);
    string sk_str;
    for(auto it = typos.begin(); it != typos.end(); it++) {
        if (it->length()>0 && tp.is_present((*it), sk_str) < T_size) {
            present.push_back(*it);
        }
    }
    return present;
}

int main(int argc, char* argv[]) {
    string pw = "HeyMyGod";
    TypTop tp("/tmp/typtop.db", pw);
    assert(tp.check(pw, true));
    cout << swapcase(pw) << " --> " <<  tp.check(swapcase(pw), false) << endl;
    cout << pw + "1" << " --> " <<  tp.check(pw + "1", false) << endl;
    cout << "The database has:" << endl;
    for(auto typo: find_what_in(tp, pw)) {
        cout << "-- " << typo << endl;
    }
    return 0;
}