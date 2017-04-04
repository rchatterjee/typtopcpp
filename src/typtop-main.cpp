//
// Created by rahul on 4/2/17.
//

#include "typtop.h"
#include <unistd.h>
#include <security/pam_appl.h>
#include <pwd.h>


string curr_user() {
    struct passwd *passwd = getpwuid ( getuid());
    return passwd->pw_name;
}

#ifdef WIN32
#define OS_SEP '\\'
#define USERDB_LOC "/somewhere/I/don't/know/"
#else
#define USERDB_LOC "/usr/local/etc/typtop/"
#define OS_SEP '/'
#endif

/**
 * Main functionalities are
 * 1> --check <username> <were_correct>
 * 2> --status <username>
 * 3> --upload [all]|<username>
 * 4> --mytypos <username>
 *
 */
string USAGE = "\nUsage: typtop [func] [options]"
        "\nfunc can be any one of --status, --upload, --mytypos"
        "\n --status <username>"
        "\n --upload [all]|<username>"
        "\n --mytypos <username>\n"
        "\nex:\n"
        "typtop --status $USER"
        "\n";

#define MAXPASS_LEN 1024

string user_db(const string& user) {
    return USERDB_LOC + user;
}

//static TypTop& user_db(const string& user) {
//    static TypTop tp(USERDB_LOC + user);
//    if (tp.is_initialized())
//        return tp;
//
//}

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>

#endif

void SetStdinEcho(bool enable = true)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

int check_password(char* argv[], int argc) {
    string pass, user;
    // Annoy some non-serious attackers, unix_chkpwd does it, so I am also doing it
    // not sure how effective it is.
    // argv expected: <argument> <username> <pw> <return_from_last_pam>
//    if (argv[1] != "--check" || isatty(STDIN_FILENO) || argc != 4 ) {
//        cerr << "inappropriate use of Unix helper binary [UID=%d]" << getuid() << endl;
//        cerr << "This binary is not designed for running in this way\n"
//             << "-- the system administrator has been informed\n";
//        sleep(10);	/* this should discourage/annoy the user */
//        return PAM_ABORT;
//    }

    if (getuid() == 0) {
        user=argv[2];
    }
    else {
        user = curr_user();
        /* if the caller specifies the username, verify that user
           matches it */
        if (user == argv[2]) {
            user = argv[2];
            /* no match -> permanently change to the real user and proceed */
            if (setuid(getuid()) != 0)
                return PAM_AUTH_ERR;
        }
    }
    TypTop tp(user_db(user));
    cin >> pass;
    if(pass.length() > MAXPASS_LEN)
        return PAM_AUTH_ERR;
    int were_correct = atoi(argv[3]);
    bool typtop_ret = tp.check(pass, bool(were_correct));
    pass.clear();
    if(typtop_ret)
        return PAM_SUCCESS;
    else
        return PAM_AUTH_ERR;
}


vector<string> find_what_in(const TypTop& tp, string const &real_pw) {
    vector<string> typos(10), present; // try more once we have a good function
    get_typos(real_pw, typos);
    string sk_str;
    for(auto it = typos.begin(); it != typos.end(); it++) {
        if (it->length()>0 && tp.is_typo_present((*it), sk_str) < T_size) {
            present.push_back(*it);
        }
    }
    return present;
}


int main(int argc, char *argv[])  {
    /*
     * Determine what the current user's name is.
     * We must thus skip the check if the real uid is 0.
     */
    if(argc < 3) {
        cerr << USAGE << endl;
        return 1;
    }

    cout << "argvs: " << argv[0] << argv[1] << argv[2] << argv[3] << endl;
    if (strncmp("--check", argv[1], 7) == 0) {
        assert(argc == 4);
        return check_password(argv, argc);
    }
    string user = argv[2];
    try {
        TypTop tp(user_db(user));
        if (strncmp("--status", argv[1], 8)) {
            assert(argc == 3);
            cerr << "IsInitialized: " << tp.is_initialized() << endl;
            // TODO: Status funciotn
        } else if (strncmp("--upload", argv[1], 8)) {
            assert(argc == 3);
            // TODO: upload funciton
        } else if (strncmp("--mytypos", argv[1], 9) == 0) {
            assert(argc == 3);
            string pass;
            cout << "Password:";
            SetStdinEcho(false);
            cin >> pass;
            SetStdinEcho(true);
            cerr << "This will going to print out your passwords.\n"
                    "Please be careful about the shoulder surfers!!"
                    "(y/n)" << endl;
            string y;
            cin >> y;
            if (tolower(y) == "y") {
                for (auto typo: find_what_in(tp, pass)) {
                    cerr << " --> " << typo << endl;
                }
            }
        } else {
            cerr << USAGE << endl;
        }
    } catch (exception& ex) {
        cerr << ex.what() << endl;
        return PAM_AUTH_ERR;
    }
    return 0;
}
