//
// Created by rahul on 4/8/17.
//

// #include "typtop.h"
// #include "catch.hpp"

#define DEBUG 1

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <assert.h>
#include "catch.hpp"

using namespace std;

static struct pam_conv conv = {
    misc_conv,
    NULL
};

#define PASS_FILE "/tmp/pass.txt"

int auth(const char *user) {
    pam_handle_t *pamh=NULL;
    int retval;
    REQUIRE(freopen(PASS_FILE, "r", stdin));
    retval = pam_start("su", user, &conv, &pamh);
    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    /* This is where we have been authorized or not. */

    if (retval == PAM_SUCCESS) {
        fprintf(stdout, "Authenticated\n");
    } else {
        fprintf(stdout, "Not Authenticated\n");
    }


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

TEST_CASE("Check Install") {
    const string user = "tmptyptop";
    SECTION("Basic") {
        fstream of(PASS_FILE, ios::in);
        copy(pws.begin(), pws.end(), ostream_iterator<string>(of, "\n"));
        of.close();
        int i=0;
        for(string pw: pws) {
            if(i<=3)
                REQUIRE(auth(user.c_str()));
            else
                REQUIRE_FALSE(auth(user.c_str()));
        }
        of.open(PASS_FILE, ios::in);
        of << pws[0];
        of << pws[4];
        of.close();
        REQUIRE(auth(user.c_str()));
        REQUIRE(auth(user.c_str()));
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
//    string pws[] = {
//
//    };
//    for(string s: pws) {
//    }
//}
