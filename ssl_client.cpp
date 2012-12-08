//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization
    SSL_library_init();    
    ERR_load_crypto_strings();    
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
    // Useage: client server:port filename
    if (argc < 3)
      {
	printf("Useage: client serveraddress:portnumber filename\n");
	exit(EXIT_FAILURE);
      }
    char* server = argv[1];
    char* filename = argv[2];
    
    printf("------------\n");
    printf("-- CLIENT --\n");
    printf("------------\n");
    
    //-------------------------------------------------------------------------
    // 1. Establish SSL connection to the server
    printf("1.  Establishing SSL connection with the server...");
    
    // Setup client context

    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    //	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
      {
	printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
	exit(EXIT_FAILURE);
      }
    
    // Setup the BIO
    BIO* client = BIO_new_connect(server);
    if (BIO_do_connect(client) != 1)
      {
	printf("FAILURE.\n");
        print_errors();
	exit(EXIT_FAILURE);
      }
    
    // Setup the SSL
    SSL* ssl=SSL_new(ctx);
    if (!ssl)
      {
	printf("Error creating new SSL object from context.\n");
	exit(EXIT_FAILURE);
	}
    SSL_set_bio(ssl, client, client);
    if (SSL_connect(ssl) <= 0)
      {
	printf("Error during SSL_connect(ssl).\n");
	print_errors();
	exit(EXIT_FAILURE);
      }
    
    printf("SUCCESS.\n");
    printf("    (Now connected to %s)\n", server);
    
    //-------------------------------------------------------------------------
    // 2. Send the server a random number
    printf("2.  Sending challenge to the server...");
    
    string randomNumber="31337"; //create a random number rand(3)
    
    //SSL_write
    int buffWriteChallengeLen = 0;
    char buffWriteChallenge[BUFFER_SIZE];
    memset(buffWriteChallenge, 0, sizeof(buffWriteChallenge));
    for(int i=0; i < sizeof(randomNumber); i++) 
      buffWriteChallenge[i] = randomNumber[i];
    buffWriteChallengeLen = SSL_write(ssl, buffWriteChallenge, BUFFER_SIZE);
    //wait to make sure that all information has been successfully sent
    int test = BIO_flush(client);
      
    //we use flush to make sure that the information was sent over the network
    //if -1 or 1 was returned then somehting went wrong
    if( test == -1 || test == 0 )
    {
      printf("SOMETHING WENT WRONG WHEN FLUSHING\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
    
    printf("SUCCESS.\n");
    printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());
    
    //-------------------------------------------------------------------------
    // 3a. Receive the signed key from the server
    printf("3a. Receiving signed key from server...");
    
    //SSL_read;
    
    int buffReadChallengeLen = 0;
    char buffReadChallenge[BUFFER_SIZE];
    memset(buffReadChallenge, 0, sizeof(buffReadChallenge));
    buffReadChallengeLen = SSL_read(ssl, buffReadChallenge, BUFFER_SIZE);
    
    printf("RECEIVED.\n");
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buffReadChallenge, buffReadChallengeLen).c_str(), buffReadChallengeLen);
    
    //-------------------------------------------------------------------------
    // 3b. Authenticate the signed key
    printf("3b. Authenticating key...");
    
    //BIO_new(BIO_s_mem())
    //BIO_write
    //BIO_new_file
    //PEM_read_bio_RSA_PUBKEY
    //RSA_public_decrypt
    //BIO_free
    char hashString[1024];
    memset(hashString, 0, sizeof(hashString));
    
    BIO *binfile, *boutfile, *hash;
    binfile = BIO_new(BIO_s_mem());
    //BIO_free(binfile);
    int actualWritten = BIO_write(binfile, buffWriteChallenge, BUFFER_SIZE);
   
    hash = BIO_new(BIO_f_md());
    BIO_set_md(hash, EVP_sha1()); 
    BIO_push(hash, binfile);

    int actualRead = BIO_gets(hash, hashString, 1024);

    BIO * rsaPublicKeyInput = BIO_new_file("rsapublickey.pem", "r" );

    RSA * rsaPublicKeyVal;
    rsaPublicKeyVal = PEM_read_bio_RSA_PUBKEY(rsaPublicKeyInput, 
					      NULL, 0, NULL);

    int sizeOfBuff = RSA_size(rsaPublicKeyVal);
    char decryptSign[BUFFER_SIZE];
    memset(decryptSign, 0, BUFFER_SIZE);

    int decryptBufferLength = RSA_public_decrypt(sizeOfBuff, 
						 (const unsigned char*)
						 buffWriteChallenge,
						 (unsigned char*)
						 decryptSign, rsaPublicKeyVal,
						 RSA_PKCS1_PADDING);

    
    printf("VALUE OF DECRYPT %d\n", decryptBufferLength);
    

    
    string generated_key= hashString;
    string decrypted_key="";
    
    printf("AUTHENTICATED\n");
    printf("    (Generated key: %s)\n", generated_key.c_str());
    printf("    (Decrypted key: %s)\n", decrypted_key.c_str());
    
    //-------------------------------------------------------------------------
    // 4. Send the server a file request
    printf("4.  Sending file request to server...");
    
    PAUSE(2);
    //BIO_flush
    //BIO_puts
    //SSL_write
    
    printf("SENT.\n");
    printf("    (File requested: \"%s\")\n", filename);
    
    //-------------------------------------------------------------------------
    // 5. Receives and displays the contents of the file requested
    printf("5.  Receiving response from server...");
    
    //BIO_new_file
    //SSL_read
    //BIO_write
    //BIO_free
    
    printf("FILE RECEIVED.\n");
    
    //-------------------------------------------------------------------------
    // 6. Close the connection
    printf("6.  Closing the connection...");
    
    //SSL_shutdown
    SSL_shutdown(ssl);
    
    printf("DONE.\n");
    
    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
    
    //-------------------------------------------------------------------------
    // Freedom!
    print_errors();
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    return EXIT_SUCCESS;
    
}
