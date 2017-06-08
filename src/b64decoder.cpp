//
// Created by Rahul Chatterjee on 6/7/17.
//

#include "pw_crypto.h"
#include <sqlite3.h>
#include <typtop.h>

using namespace std;

string mydecode(string& s) {
    return b64decode(s);
}

sqlite3* open_db(const char* dname) {
    sqlite3 *db;

    int rc = sqlite3_open(dname, &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return(0);
    }else{
        fprintf(stderr, "Opened database successfully\n");
    }
    return db;
}

void close_db(sqlite3* db) {
    sqlite3_close(db);
}

static int callback(void *data, int argc, char **argv, char **azColName){
    int i;
    assert(argc == 3);
    printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    printf("\n");
    return 0;
}

int main(int argc, char *argv[]) {
    sqlite3* db = open_db(argv[1]);
    string sql = "select * from logdata";
    int rc;
    char *zErrMsg = 0;
    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }else{
        fprintf(stdout, "Table created successfully\n");
    }
    string in;
    return 0;
}