#include "pw_crypto.h"
#include "typtop.h"

int main() {
    for(std::string line; std::getline(std::cin, line);) {
        Logs lgs;
        // lgs.ParseFromString(b64decode(line));
        // cout << lgs.DebugString() << endl;
        string l = b64decode(line);
        cout << l.size() << endl << b64decode(line);
    }
    return 0;
}