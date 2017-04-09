#define _XOPEN_SOURCE 700


#ifndef __APPLE__
#  include <security/_pam_macros.h>
#  include <security/pam_ext.h>
#  include <security/pam_modutil.h>
#else

#include <security/pam_appl.h>

#endif

#include <syslog.h>
#include <security/pam_modules.h>
#include <string>
#include <stdio.h>
#include <cstdlib>
#include <pwd.h>

#ifdef __APPLE__

/* pam_syslog is missing in apple, this is a function taken from
   https://git.reviewboard.kde.org/r/125056/diff/3#4
*/
void pam_vsyslog(const pam_handle_t *ph, int priority, const char *fmt, va_list args) {
    return;
    char *msg = NULL;
    const char *service = NULL;
    int retval;
    retval = pam_get_item(ph, PAM_SERVICE, (const void **) &service);
    if (retval != PAM_SUCCESS)
        service = NULL;

    if (vsprintf(msg, fmt, args) < 0) {
        syslog(LOG_CRIT | LOG_AUTHPRIV, "cannot allocate memory in vasprintf: %m");
        return;
    }
    syslog(priority | LOG_AUTHPRIV, "%s%s%s: %s",
           (service == NULL) ? "" : "(",
           (service == NULL) ? "" : service,
           (service == NULL) ? "" : ")", msg);
    free(msg);
}

void pam_syslog(const pam_handle_t *ph, int priority, const char *fmt, ...) {
    return;
    va_list args;
    va_start(args, fmt);
    pam_vsyslog(ph, priority, fmt, args);
    va_end(args);
}
#endif

using namespace std;
// supported management groups
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD

#ifndef TYPTOP_BIN_LOC
#define TYPTOP_BIN_LOC "/usr/local/bin/typtop"
#endif

static int
call_typtop(pam_handle_t *pamh, const char *user, const char *passwd, int chkwd_ret) {
    // chkwd_ret is set to PAM_SUCCESS or PAM_AUTH_ERR, and they are 0 and >0 respectively
    // typtop expects boolean for those values, and better to use 1 for PAM_SUCCESS and 0
    // for other failure modes.
    if (!getpwnam(user))
        return PAM_AUTH_ERR;

    string cmd = "/usr/local/bin/typtop --check " + string(user);
    cmd += " " + to_string(chkwd_ret);
    // cmd += " " + string(user);
    int retval = PAM_AUTH_ERR;

    // printf("cmd=%s\n", cmd);
    FILE *fp = popen(cmd.c_str(), "w");
    if (fp == NULL) {
        pam_syslog(pamh, LOG_ERR, "Typtop could not be opened. Sorry! retval=%d\n", retval);
        return chkwd_ret==2?PAM_SUCCESS:PAM_AUTH_ERR;
    }
    fprintf(fp, "%s", passwd);
    int status = pclose(fp);
    int _exit_status = WEXITSTATUS(status);  // exit status 0 means success, 1 means failure.
    if (chkwd_ret==2)
        return PAM_SUCCESS;

    // if a process fails then the exit status is -1
    return _exit_status == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}


/*  Runs TypToP, fetching the entered password using `pam_get_authtok`
    If
*/
__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret_pam_unix = 1;  // default ret_pam_unix is pam_failure
    const char *name;
    const char *passwd;
    int i;
    for (i = 1; i < argc; ++i) {
        if (string(argv[i]) == "first_time") {
            ret_pam_unix = 1;
        } else if (string(argv[i]) == "second_time") {
            ret_pam_unix = 2;
        }
    }

    if (ret_pam_unix == 1) {
        pam_syslog(pamh, LOG_NOTICE, "Trying for the first_time");
    } else {
        pam_syslog(pamh, LOG_NOTICE, "Trying second time, somehow first attempt failed.");
    }

    if (pam_get_user(pamh, &name, "Username") != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "couldn't get username from PAM stack");
        return PAM_USER_UNKNOWN;
    }

    int retval = pam_get_authtok(pamh, PAM_AUTHTOK, &passwd, "pASSWORD:");
    if (retval != PAM_SUCCESS || passwd == NULL) {
        pam_syslog(pamh, LOG_WARNING, "couldn't find cached password or password is blank");
        return PAM_AUTH_ERR;
    } else {
        return call_typtop(pamh, name, passwd, ret_pam_unix);
/*
        if (retval == 0) {
            if (ret_pam_unix != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_NOTICE, "typtop allowed typo-ed password");
            }
            pam_syslog(pamh, LOG_NOTICE, "returning PAM_SUCCESS.");
            return PAM_SUCCESS;
        } else {
            pam_syslog(pamh, LOG_NOTICE, "typtop either failed or check did not pass. retval=%d", retval);
            return ret_pam_unix;
        }*/
    }
}


__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv) {
    int retval = PAM_SUCCESS;
    pam_syslog(pamh, LOG_NOTICE, "called pam_sm_setcred. flag=%d", flags);
    return retval;
}

__attribute__((visibility("default")))
PAM_EXTERN int pam_sm_chkauthtok(pam_handle_t *pamh, int flags, int argc, char **argv) {
    static const char old_password_prompt[] = "(Should Never reach here. Try entering your old Password):";
    static const char new_password_prompt[] = "(Should Never reach here. Try entering your new Password):";

    int retval = PAM_SUCCESS;
    const char *user;
    const char *new_password = NULL;
    const char *old_password = NULL;

    if (flags & PAM_PRELIM_CHECK)
        return PAM_SUCCESS;

    if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_WARNING, "Could not get username from pam_stack");
        return retval;
    }

    if (PAM_SUCCESS != (retval = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void **) &old_password))) {
        pam_syslog(pamh, LOG_WARNING, "Could not get username from pam_stack");
        return PAM_USER_UNKNOWN;
    }
    if (NULL == old_password &&
        PAM_SUCCESS != (retval = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &old_password, old_password_prompt)))
        return retval;
    if (PAM_SUCCESS != (retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &new_password)))
        return retval;
    if (NULL == new_password &&
        PAM_SUCCESS != (retval = pam_get_authtok(pamh, PAM_AUTHTOK, &new_password, new_password_prompt)))
        return retval;

    // update password in typtop
    // typtop = TypTop(user);
    // retval = typtop.update_pw(old_pw, new_pw);
    return retval;
}

#ifdef PAM_MODULE_ENTRY

PAM_MODULE_ENTRY("pam_typtop");
#endif
