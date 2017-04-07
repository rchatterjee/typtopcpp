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
const string url = "https://ec2-54-209-30-18.compute-1.amazonaws.com/submit";

// TODO add CA file

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

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);
    stringstream payloadstream;
    payloadstream << "uid=" << uid
            << "&data=" << log
            << "&test=" << 1;
    string payload;
    payloadstream >> payload;

    /* get a curl handle */
    curl = curl_easy_init();
    FILE *devnull = fopen("/dev/null", "w");
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.size());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        /* Add the certificate */
        curl_easy_setopt(curl, CURLOPT_CAINFO, CAFILE);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK){
            LOG_ERROR << "curl_easy_perform() failed: "<< curl_easy_strerror(res)
                 << "\nCAFILE: " << CAFILE << endl;
            // try old cert once
            curl_easy_setopt(curl, CURLOPT_CAINFO, OLD_CAFILE);
            res = curl_easy_perform(curl);
            if(res != CURLE_OK){
                LOG_ERROR << "curl_easy_perform() failed: "<< curl_easy_strerror(res)
                     << "\nCAFILE: " << OLD_CAFILE << endl;
            }
        }
        /* always cleanup */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    fclose(devnull);
    return (res == CURLE_OK);
}

