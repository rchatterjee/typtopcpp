//
// Created by rahul on 4/2/17.
//

#include "typtop.h"
#include "typtopconfig.h"
#include <unistd.h>
#include <security/pam_appl.h>
#include <pwd.h>



string curr_user() {
    struct passwd *passwd = getpwuid ( getuid());
    return passwd->pw_name;
}

/**
 * Main functionalities are
 * 1> --check <username> <were_correct>
 * 2> --status <username>
 * 3> --upload <username>
 * 4> --mytypos <username>
 * 5> --mylogs <username>
 * 6> --participate <username> [yes]|no
 * 7> --allowtypo <username> [yes]|no
 * 8> --change-typopolicy <username>
 * 9> --uninstall (Have to be root)
 * 10> --version
 */
string USAGE = "\nUsage: typtop [func] [options]"
        "\nfunc can be any one of --status, --upload, --mytypos, [and --check]"
        "\n --check <username> <were_correct>"
        "\n --status <username>"
        "\n --upload <username>"
        "\n --mytypos <username>"
        "\n --mylogs <username>\n"
        "\n --participate <username> [yes]|no"
        "\n --allowtypo <username> [yes]|no"
        "\n --change-typopolicy <username>\n"

        "\n --uninstall"
        "\n --install\n"
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
    // Annoy some non-serious attackers, unix_chkpwd does it, so I am also doing it
    // not sure how effective it is.
    // argv expected: <argument> <username> <pw> <return_from_last_pam>
    // check username validity
    // TODO : enable this
    if (strncmp(argv[1], "--check", 7) != 0 || isatty(STDIN_FILENO) || argc != 4 ) {
        cerr << "inappropriate use of Unix helper binary [UID=" << getuid() << "]\n"
                "from tty=" << ttyname(STDIN_FILENO) << endl;
        cerr << "This binary is not designed for running in this way\n"
             << "-- the system administrator has been informed\n";
        sleep(10);	/* this should discourage/annoy the user */
        return PAM_ABORT;
    }

    if (seteuid(0) != 0){
        cerr << "Not running as root: " << getuid() << endl;
        return PAM_AUTH_ERR;
    }
    assert(geteuid() == 0); // if it's uid is not root, no point running further. TODO: make it for shadow

    string user = argv[2];
    int were_correct = atoi(argv[3]);
    string pw;
    cin >> pw;
    TypTop tp(user_db(user));
    // cerr << "\nPassword Received: " << pw << endl;
    if(pw.length() > MAXPASS_LEN)
        return PAM_AUTH_ERR;
    PAM_RETURN pret = (were_correct==2)?SECOND_TIME:FIRST_TIME;
    bool typtop_ret = tp.check(pw, pret, true);
    pw.clear();
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

int read_int_from_cin(string prompt, int _default, int min_l, int max_l) {
    int ret = _default;
    string input = "";
    while (true) {
        int _t;
        cout << endl << prompt;
        getline(cin, input);
        if(input.length() <= 1) break;
        stringstream myStream(input);
        if (myStream >> _t && _t <= max_l && _t >= min_l) {
            ret = _t;
            break;
        }
    }
    return ret;
}

void set_typo_policy(TypTop& tp) {
    int ed_cutoff = 1;
    int abs_entcutoff = 10;
    int rel_entcutoff = 3;

    cerr << "Current typo-policy:\n";
    auto tpolicy = tp.get_typo_policy();
    cerr << "\t EditDistance Cutoff: " << tpolicy.edit_cutoff() << endl
         << "\t Absolute Entropy Cutoff: " << tpolicy.abs_entcutoff() << endl
         << "\t Relative Entropy Cutoff: " << tpolicy.rel_entcutoff() << endl;
    cerr << "\n----------------------------------------------------------------------------------\n";
    cerr << "This settings decide what typos will be considered for tolerating into the cache.\n"
            "There are three parameter that can be tuned for this. \n"
            "1) Edit-distance cutoff: The edit distance between the typo and real password. This \n"
            "   is a distance to decide how different the typo is. So, if this threshold is set to 1,\n"
            "   then 'supersec2' and 'supersec3' will be considered typos of 'Supersec2', but not 'supersec34'\n"
            "\n"
            "2) Absolute cutoff of entropy: how easy to guess typos should be considered.\n"
            "   For example, if this threshold is set ot 10, then '12345!6' will be considered as typo of\n"
            "   '1234516', but not '123456', though both of them are within edit distance 1.\n"
            "\n"
            "3) Relative entropy cutoff: how weaker the typo will be allowed. A default value of this is set to\n"
            "   3, thus 'Password1&' will be allowed as a typo of 'Password17' but not 'Password1'\n"
            "\n\nI would recommend read the paper on TypTop before trying to change this values.\n\n";
    ed_cutoff = read_int_from_cin("How far typo should be allowed? Edit-cutoff (0-3) [1]: ", 1, 0, 3);
    abs_entcutoff = read_int_from_cin("Absolute entropy cutoff (0-30) [10]: ", 10, 0, 30);
    rel_entcutoff = read_int_from_cin("Relative entropy cutoff (0-20) [3]: ", 3, 0, 20);
    tp.set_typo_policy(ed_cutoff, abs_entcutoff, rel_entcutoff);
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
        cerr << "Typtop (" << typtop_VERSION_MAJOR << "." << typtop_VERSION_MINOR << ")";
#ifdef DEBUG
        cerr << "  (Running in DEBUG mode)";
#endif
        cerr << "\n" << USAGE << endl;
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
            if(tp.send_log(0))  // send logs always truncates the db
                cerr << "The logs are uploaded successfully. :)" << endl;
            else
                cerr << "Something went wrong. Check last few line of /tmp/typtop.log file for details." << endl;
        } else if (strncmp("--mytypos", argv[1], 9) == 0 && argc==3) {
            string pass;
            cout << "Password:";
            SetStdinEcho(false);
            std::getline(std::cin, pass);
            SetStdinEcho(true);
            cerr << "This is going to print out your passwords.\n"
                    "Please be careful about the shoulder surfers!!"
                    "(y/n)" << endl;
            string y;
            cin >> y;
            if (tolower(y) == "y") {
                for (auto typo: find_what_in(tp, pass)) {
                    cerr << " --> " << typo << endl;
                }
            }
        } else if (strncmp("--mylogs", argv[1], 5) == 0 && argc==3) {
            tp.print_log();
        } else if (strncmp("--install", argv[1], 9) == 0 && (argc==2 || argc==3)) {
            if(argc==3)
                cout << __LINE__ << " (argc=3): Installed: " << (system("sudo bash /usr/local/bin/typtop.postinst 1")?"No":"Yes")<< endl;
            else
                cout << __LINE__ << " (argc!=3): Installed: " << (system("sudo bash /usr/local/bin/typtop.postinst")?"No":"Yes")<< endl;
        } else if (strncmp("--uninstall", argv[1], 11) == 0 && (argc==2 || argc==3)) {
            if(geteuid() != 0) {
                cerr << "Need to be root to be able to call this!" << endl;
                exit(-1);
            }
            string y;
            if(argc==3 && string(argv[2])=="-y")
                y = "y";
            else {
                cout << "Are you sure you want to uninstall Typtop. (y/N):";
                cin >> y;
            }
            if (y == "y" || y == "Y") {
                int ret = system("sudo bash /usr/local/bin/typtop.prerm -disengage");
                if (ret==0)
                    cerr << "The typtop has been disengaged from your authentication system.\n"
                            "The binary might be still there and you can remove it manually.\n"
                            "The data file is left in " << USERDB_LOC << ", just in case you change\n"
                            "your mind. You can delete the directory for safety."
                         << endl;
                else
                    cerr << "There was some issues with uninstalling typtop. Can you check by re-logging in?\n"
                         << "If everything works, then you are good to go. Delete typtop executable, \n"
                         << "and " << USERDB_LOC << " directory for your safety." << endl;
                // TODO: remove the files in manifest file
            }
        } else if (strncmp("--participate", argv[1], 13)==0 && argc==4) {
            bool allow = true;
            if (strncasecmp(argv[3], "no", 2)==0)
                allow = false;
            cerr << "Setting participate: " << allow << " " << argv[3] << endl;
            tp.allow_upload(allow);
        } else if (strncmp("--allowtypo", argv[1], 13) == 0 && argc==4) {
            bool allow = true;
            if (strncasecmp(argv[3], "no", 2)==0)
                allow = false;
            cerr << "Setting allow typo login: " << allow << endl;
            tp.allow_typo_login(allow);
        } else if (strncmp("--change-typopolicy", argv[1], 19) == 0 && argc==3) {
            set_typo_policy(tp);
        } else {
                cerr << USAGE << endl;
        }
    } catch (exception& ex) {
        cerr << __FILE__ << __func__ << ex.what() << endl;
        return PAM_AUTH_ERR;
    }
    return 0;
}
