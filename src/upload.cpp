/**
 * Created by rahul on 4/7/17.
 * File to send the data to the amazon server
 *
 */

#include <stdio.h>
#include <curl/curl.h>
#include <string>
#include "typtopconfig.h"
#include "plog/Log.h"

using namespace std;


// const string url = "https://ec2-54-209-30-18.compute-1.amazonaws.com/submit";
const string url = UPLOAD_URL;
const string key =  "a40648638b48abf2159f9331cbab9cb3ae81d8cd247c145942c3cce9c708ae89";
/**
 * Sends the data to the amazon server. It assumes all the fields are url encoded,
 * and will not try to encode.
 * @param uid : The uid of the device, got by get_install_id()
 * @param log : The serialized logs
 * @param test : 1 to send to test db, 0 to send real db
 * @return : success code
 */

int send_log_to_server(const string uid, const string log, int test=1) {
    CURL *curl;
    CURLcode res = CURLE_SEND_ERROR;
    // struct curl_slist *headers = NULL;                      /* http headers to send with request */

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);
    stringstream payloadstream;
    payloadstream << "uid=" << uid << "#"
                  << typtop_VERSION_MAJOR << "." << typtop_VERSION_MINOR << "." << typtop_VERSION_PATCH
                  << "&data=" << log
                  << "&test=" << test
                  << "&key=" << key;
    LOG_INFO << "Sending to test=" << test;
    string payload;
    payloadstream >> payload;
    long response_code = 404;

    /* get a curl handle */
    curl = curl_easy_init();
    FILE *devnull = fopen("/dev/null", "w");
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.size());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        /* Add the certificate */
        // curl_easy_setopt(curl, CURLOPT_CAINFO, CAFILE);

        // Till I can fix this weird bug
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);


        /* set content type */
//        headers = curl_slist_append(headers, "Accept: application/json");
//        headers = curl_slist_append(headers, "Content-Type: application/json");
//        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        /* set timeout */
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1.5L);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK){
            LOG_ERROR << "curl_easy_perform() failed: "<< curl_easy_strerror(res);
//            // try old cert once
//            curl_easy_setopt(curl, CURLOPT_CAINFO, OLD_CAFILE);
//            res = curl_easy_perform(curl);
//            if(res != CURLE_OK){
//                LOG_ERROR << "curl_easy_perform() failed: "<< curl_easy_strerror(res)
//                     << "\nCAFILE: " << OLD_CAFILE << endl;
//            }
        } else
            curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);

        /* always cleanup */
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
//    curl_slist_free_all(headers);
    fclose(devnull);
    return (response_code == 200);
}

