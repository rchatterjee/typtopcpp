//
// Created by rahul on 4/2/17.
//

#include "typtop.h"
// #include <unistd.h>
#include <security/pam_appl.h>
#include <pwd.h>
#include <zconf.h>


string curr_user() {
    struct passwd *passwd = getpwuid ( getuid());
    return passwd->pw_name;
}

#ifdef WIN32
#define OS_SEP '\\'
#define USERDB_LOC "/somewhere/I/don't/know/"
#else
#define USERDB_LOC "/usr/local/etc/typtop.d/"
#define OS_SEP '/'
#endif

/**
 * Main functionalities are
 * 1> --check <username> <were_correct>
 * 2> --status <username>
 * 3> --upload [all]|<username>
 * 4> --mytypos <username>
 * 5> --log <username>
 */
string USAGE = "\nUsage: typtop [func] [options]"
        "\nfunc can be any one of --status, --upload, --mytypos, [and --check]"
        "\n --check <username> <were_correct>"
        "\n --status <username>"
        "\n --upload [all]|<username>"
        "\n --mytypos <username>"
        "\n --log <username>\n"
        "\n --uninstall\n"
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

void SetStdinEcho(bool enable = true) {
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
    // check username validity
    // TODO : enable this
//    if (argv[1] != "--check" || isatty(STDIN_FILENO) || argc != 4 ) {
//        cerr << "inappropriate use of Unix helper binary [UID=%d]" << getuid() << endl;
//        cerr << "This binary is not designed for running in this way\n"
//             << "-- the system administrator has been informed\n";
//        sleep(10);	/* this should discourage/annoy the user */
//        return PAM_ABORT;
//    }

    if (seteuid(0) != 0){
        cerr << "Not running as root: " << getuid() << endl;
        return PAM_AUTH_ERR;
    }
    assert(geteuid() == 0); // if it's uid is not root, no point running further. TODO: make it for shadow
    assert(argc == 4);  // --check <user> 0/1

    user = argv[2];
    TypTop tp(user_db(user));
    cin >> pass;
    // cerr << "\nPassword Received: " << pass << endl;
    if(pass.length() > MAXPASS_LEN)
        return PAM_AUTH_ERR;
    int were_correct = atoi(argv[3]);
    PAM_RETURN pret = (were_correct==2)?SECOND_TIME:FIRST_TIME;
    bool typtop_ret = tp.check(pass, pret);
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

void ensure_root() {
    if (seteuid(0) != 0){
        cerr << "Not running as root. Your uid=" << geteuid() << endl;
        cerr << "Aborting!!" << endl;
        exit(-1);
    }
}

int main(int argc, char *argv[])  {
    /*
     * Determine what the current user's name is.
     * We must thus skip the check if the real uid is 0.
     */
    if(argc<2) {
        cerr << USAGE << endl;
        return -1;
    }
//    cout << "argvs: " << argv[0] << " " << argv[1] << " " << argv[2]
//         << " " << argv[3] << endl;
    if (strncmp("--check", argv[1], 7) == 0) {
        assert(argc == 4);
        return check_password(argv, argc);
    }
    string user = argc>2?argv[2]:"";
    ensure_root();
    try {
        TypTop tp(user_db(user));
        if (strncmp("--status", argv[1], 8) == 0 && argc==3) {
            cerr << "IsInitialized: " << tp.is_initialized() << endl;
            tp.status();
        } else if (strncmp("--upload", argv[1], 8) == 0 && argc==3) {
            tp.send_log();  // send logs always truncates the db
                cerr << "If this is the only line you are seeing then logs "
                     << "are uploaded successfully. :)" << endl;
        } else if (strncmp("--mytypos", argv[1], 9) == 0 && argc==3) {
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
        } else if (strncmp("--log", argv[1], 5) == 0 && argc==3) {
            tp.print_log();
        } else if (strncmp("--uninstall", argv[1], 11) == 0 && argc==2) {
            string y;
            cout << "Are you sure you want to uninstall Typtop. (y/N):";
            cin >> y;
            if (y == "y" || y == "Y") {
                system("sudo bash /usr/local/bin/typtop.prerm");
                cout << "The typtop has been disengaged from your authentication system. "
                     << "The binary is still there and you can remove it manually." << endl;
                // TODO: remove the files in manifest file
            }
        } else {
            cerr << USAGE << endl;
        }
    } catch (exception& ex) {
        cerr << __FILE__ << __func__ << ex.what() << endl;
        return PAM_AUTH_ERR;
    }
    return 0;
}
