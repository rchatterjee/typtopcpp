//
// Created by Rahul Chatterjee on 6/7/17.
//

#include "pw_crypto.h"
// #include <sqlite3.h>
// #include <typtop.h>

using namespace std;

string mydecode(string& s) {
    return b64decode(s);
}

//sqlite3* open_db(const char* dname) {
//    sqlite3 *db;
//
//    int rc = sqlite3_open(dname, &db);
//    if( rc ){
//        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
//        return(0);
//    }else{
//        fprintf(stderr, "Opened database successfully\n");
//    }
//    return db;
//}
//
//void close_db(sqlite3* db) {
//    sqlite3_close(db);
//}
//
////#include <google/protobuf/util/json_util.h>
//static int callback(void *data, int argc, char **argv, char **azColName){
////    assert(argc == 3);
////    string ret[8];
////    std::map<string&, string&> name_map;
////    Logs logs;
////    string uid;
////    int lid;
////    for(int i=0; i<argc; i++){
////        if (strcmp(azColName[i], "data")==0){
////            logs.ParseFromString(b64decode(argv[i]));
////        } else if (strcmp(azColName[i], "uid")) {
////            Log l = logs.l(i);
////        }
////
////    }
//    return 0;
//}
//
//int main(int argc, char *argv[]) {
//    sqlite3* db = open_db(argv[1]);
//    string sql = "select * from logdata";
//    int rc;
//    char *zErrMsg = 0;
//    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &zErrMsg);
//    if( rc != SQLITE_OK ){
//        fprintf(stderr, "SQL error: %s\n", zErrMsg);
//        sqlite3_free(zErrMsg);
//    }else{
//        fprintf(stdout, "Table created successfully\n");
//    }
//    string in;
//    return 0;
//}