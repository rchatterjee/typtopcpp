//
// Created by rahul on 4/8/17.
//

// #include "typtop.h"
// #include "catch.hpp"

#define DEBUG 1
#ifdef __APPLE__
#include <security/pam_appl.h>
#include <security/openpam.h>
#else
#include <security/pam_misc.h>
#include <security/pam_ext.h>
#endif

#include <stdio.h>
#include <fstream>
#include <iostream>
// #include "catch.hpp"

using namespace std;

static struct pam_conv conv = {
    misc_conv,
    NULL
};

#define PASS_FILE "/tmp/pass.txt"

int auth(const char *user) {
    pam_handle_t *pamh=NULL;
    int retval;
    // REQUIRE(freopen(PASS_FILE, "r", stdin) != NULL);
    retval = pam_start("su", user, &conv, &pamh);
    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */
    string pw;

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */
    /* This is where we have been authorized or not. */
    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "su: failed to release authenticator\n");
        exit(1);
    }

    return ( retval == PAM_SUCCESS ? 1:0 );       /* indicate success */
}

 const vector<string> pws = {
         "hello_pass", // 0, ed=0
         "Hello_pass",  // 1, ed=1
         "hello_pass1", // 2, ed=1
         "HELLO_PASS",  // 3, ed=1
         "hlelo_pass", // 4, ed=1
         "Hello_Pass",  // 5, ed=2
 };
void call_auth(size_t cnt, int **pipes) {
    close(pipes[0][1]);
    dup2(pipes[0][0], STDIN_FILENO);
    close(pipes[1][0]);
    dup2(pipes[1][1], STDOUT_FILENO);
    string user;
    string pw;
    int i = 0;
    do{
        cin >> user;
        // cin >> pw;
        // cout << "<" << user << ">" << " --> <" << pw << ">\n";
        // cerr << "<" << user << ">" << " --> <" << pw << ">\n";
        cout << auth(user.c_str());
    } while(user.size()>0 && i++<4);
}

 TEST_CASE("Check Install") {
     const string user = "tmptyptop";
     SECTION("Basic") {
         fstream of(PASS_FILE, ios::out);
         copy(pws.begin(), pws.end(), ostream_iterator<string>(of, "\n"));
         of.close();
         int **pipes = new int*[2];  // 0: test -> auth(stdin), 1: auth(stdout) -> test
         pipes[0] = new int[2]; pipes[1] = new int[2];
         REQUIRE_FALSE(pipe(pipes[0]));
         REQUIRE_FALSE(pipe(pipes[1]));
         pid_t  pid = fork();
         int ret=0;
         char buf[100] = "";
         if(pid==0) {// child
             call_auth(pws.size(), pipes);
         } else {
             close(pipes[0][0]); close(pipes[1][1]);
             write(pipes[0][1], (user + "\n" + pws[0] + "\n") .c_str(),
                   user.size() + pws[0].size() + 3);
             // write(pipes[0][1], pws[0].c_str(), pws[0].size());
             // read(pipes[1][0], (void *)&ret, 4);
             read(pipes[1][0], buf, 100);
             cout << "----> " << buf << endl;
             CHECK(ret == 1);
         }
//         int i=0;
//         for(string pw: pws) {
//             if(i<=3)
//                 REQUIRE(auth(user.c_str()));
//             else
//                 REQUIRE_FALSE(auth(user.c_str()));
//             i++;
//         }
//         of.open(PASS_FILE, ios::in);
//         of << pws[0];
//         of << pws[4];
//         of.close();
//         REQUIRE(auth(user.c_str()));
//         REQUIRE(auth(user.c_str()));
     }
 }


//int main(int argc, char *argv[])
//{
//    const char *user="nobody";
//
//    if (argc < 3) {
//        cout << "USAGE: " << argv[0] << " <user> <password>" << endl;
//        return -1;
//    }
//    user = argv[1];
//    const char *pw = argv[2];
//    fstream of(PASS_FILE, ios::out);
//    of << pw << endl;
//    of.close();
//    cout << "Pw: " << pw << auth(user) << endl;
//    return 0;
//}
