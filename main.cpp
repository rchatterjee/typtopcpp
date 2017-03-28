#include <iostream>
#include "pw_crypto.h"

int main() {
    std::cout << "Hello, World!" << std::endl;
    (void)argc; (void)argv;

    string password = "Super secret password";
    if(argc >= 2 && argv[1] != NULL)
        password = string(argv[1]);

    string message = "Now is the time for all good men to come to the aide of their country";
    if(argc >= 3 && argv[2] != NULL)
        message = string(argv[2]);

    try {

        // For derived parameters
        SecByteBlock ekey(16), iv(16), akey(16);

        DeriveKeyAndIV(password, "authenticated encryption example", 100,
                       ekey, ekey.size(), iv, iv.size(), akey, akey.size());

        // Create and key objects
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());
        HMAC< SHA256> hmac1;
        hmac1.SetKey(akey, akey.size());
        HMAC< SHA256> hmac2;
        hmac2.SetKey(akey, akey.size());

        // Encrypt and authenticate data

        string cipher, recover;
        StringSource ss1(message, true /*pumpAll*/,
                         new StreamTransformationFilter(encryptor,
                                                        new HashFilter(hmac1,
                                                                       new StringSink(cipher),
                                                                       true /*putMessage*/)));

        // Authenticate and decrypt data
        static const word32 flags = CryptoPP::HashVerificationFilter::HASH_AT_END |
                                    CryptoPP::HashVerificationFilter::PUT_MESSAGE |
                                    CryptoPP::HashVerificationFilter::THROW_EXCEPTION;


        StringSource ss2(cipher, true /*pumpAll*/,
                         new HashVerificationFilter(hmac2,
                                                    new StreamTransformationFilter(decryptor,
                                                                                   new StringSink(recover)),
                                                    flags));

        // Print stuff

        cout << "Password: " << password << endl;

        PrintKeyAndIV(ekey, iv, akey);

        cout << "Message: " << message << endl;

        cout << "Ciphertext+MAC: ";
        HexEncoder encoder(new FileSink(cout));

        encoder.Put((byte*)cipher.data(), cipher.size());
        encoder.MessageEnd(); cout << endl;

        cout << "Recovered: " << recover << endl;
    }
    catch(CryptoPP::Exception& ex)
    {
        cerr << ex.what() << endl;
    }

    return 0;
}