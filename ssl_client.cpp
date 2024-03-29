//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <fstream>
using namespace std;
#include <openssl/rand.h>
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
    
    int sizeOfRandNumber = 64;  //harcoded size of random number
    char randomNumber[sizeOfRandNumber];
    if( RAND_bytes((unsigned char*)randomNumber,sizeOfRandNumber) == -1 )
      {
	print_errors();
	exit(-1);
      }

    //SSL_write
    int buffWriteChallengeLen = sizeOfRandNumber;
    char buffWriteChallenge[buffWriteChallengeLen];
    memset(buffWriteChallenge, 0, buffWriteChallengeLen);
    for(int i=0; i < sizeOfRandNumber; i++) 
      buffWriteChallenge[i] = randomNumber[i];


    //get the public key
    BIO * rsaPublicKeyInput = BIO_new_file("rsapublickey.pem", "r" );
    
    //get the RSA public key parameters
    RSA * rsaPublicKeyVal;
    rsaPublicKeyVal = PEM_read_bio_RSA_PUBKEY(rsaPublicKeyInput, 
					      NULL, 0, NULL);
    
    //buffer we will be putting the signiture value into
    int sizeOfChallengeEnc = RSA_size(rsaPublicKeyVal)-11;
    char challengeEnc[sizeOfChallengeEnc];
    memset(challengeEnc, 0, sizeOfChallengeEnc);  
    
    //encrypt the challenge number
    int encryptBufferLength = RSA_public_encrypt(sizeOfRandNumber, 
						 (const unsigned char*)
						 (buffWriteChallenge),
						 (unsigned char*)
						 challengeEnc,
						 rsaPublicKeyVal,
						 RSA_PKCS1_PADDING);   

    for(int i=0; i < sizeof(randomNumber); i++) 
      buffWriteChallenge[i] = randomNumber[i];


    printf("\n    The orignal challenge value is: %s", buff2hex((const unsigned char*)randomNumber,sizeOfRandNumber).c_str());
    printf("\n    The encrypted challenge value is: %s\n",buff2hex((const unsigned char*)challengeEnc, encryptBufferLength).c_str());


    buffWriteChallengeLen = SSL_write(ssl, challengeEnc, encryptBufferLength);

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
    printf("    (Challenge sent: \"%s\")\n", buff2hex((const unsigned char*)challengeEnc, encryptBufferLength).c_str());
    
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
    
    //create the hash number
    binfile = BIO_new(BIO_s_mem());
    
    //create a stream for us to chain the hash stream
    int actualWritten = BIO_write(binfile, buffWriteChallenge, BUFFER_SIZE);
    
    //create the hash stream
    hash = BIO_new(BIO_f_md());
    BIO_set_md(hash, EVP_sha1());
    //chain the hash stream
    BIO_push(hash, binfile);  

    //get the value from the hash stream and record that size
    int actualRead = BIO_gets(hash, hashString, BUFFER_SIZE);

    
    //decrypt the number sent from the server
   
    //create a new buffer to store the decrypted value
    int sizeOfBuff = buffReadChallengeLen;
    char decryptSign[sizeOfBuff];
    memset(decryptSign, 0, sizeOfBuff);
    
    //decrypt the buffer and store the size of the new key
    int decryptBufferLength = RSA_public_decrypt(sizeOfBuff,
						 (const unsigned char*)
						 buffReadChallenge,
						  (unsigned char*)
						 decryptSign, 
						 rsaPublicKeyVal,
						 RSA_PKCS1_PADDING);    
    //check if there is an error
    if( decryptBufferLength == -1 ){
      print_errors();
      exit(-1);
    }
    
    string generated_key= hashString;
    string decrypted_key= decryptSign;

    //if not same then Server could not be authenticated
    if( generated_key != decrypted_key ){
      printf("\nServer could not be authenticated... Ending Simulation\n");
      exit(0);
    }
    
    //print the outputs
    printf("AUTHENTICATED\n");
    printf("    (Generated key: %s)\n", buff2hex((const unsigned char*)hashString,actualRead).c_str());
    printf("    (Decrypted key: %s)\n", buff2hex((const unsigned char*)decryptSign,decryptBufferLength).c_str());
    
    //-------------------------------------------------------------------------
    // 4. Send the server a file request
    printf("4.  Sending file request to server...");
    
    PAUSE(2);
    //BIO_flush
    //BIO_puts
    //SSL_write

    
    //buffer we will be putting the filename value into
    int sizeOfEncFileName = RSA_size(rsaPublicKeyVal) - 11;
    char encFileName[sizeOfEncFileName];
    memset(encFileName, 0, sizeOfEncFileName);  
    
    //encrypt the challenge number
    int encFileNameSize = RSA_public_encrypt(sizeof(filename)+1, 
					     (const unsigned char*)
					     (filename),
					     (unsigned char*)
					     encFileName,
					     rsaPublicKeyVal,
					     RSA_PKCS1_PADDING); 

    

    SSL_write(ssl, encFileName, encFileNameSize );
    BIO_flush(client);

    
    
    printf("SENT.\n");
    printf("    (File requested: \"%s\")\n", filename);
    printf("    (File requesteds encryption vale: \"%s\")\n",buff2hex((const unsigned char*)encFileName, encFileNameSize).c_str());
    //-------------------------------------------------------------------------
    // 5. Receives and displays the contents of the file requested
    printf("5.  Receiving response from server...");
    
    //BIO_new_file
    //SSL_read
    //BIO_write
    //BIO_free
    
    //write to the file outputFile.txt
    BIO * fileWrite = BIO_new_file("outputFile.txt","w");
  
    int bytesRead = 1;
    bool isStreamEmpty = true;
    while( bytesRead > 0 )
      {
	int maxLineSize = BUFFER_SIZE;
	char lineWrite[maxLineSize];
	memset(lineWrite, 0, maxLineSize);
	
	//read the line from the server in
	bytesRead = SSL_read(ssl, lineWrite, maxLineSize );
	
	if( bytesRead > 0 ) isStreamEmpty = false;
	
	if( bytesRead == 0 )
	  {
	    if( isStreamEmpty ){
	      printf("\nThere was either no information sent from the server or the there was a problem sending\n");
	      exit(-1);
	    }
	    else{
	      printf("\nReached the end of file\n");
	      break;
	    }
	  }
	    
	    
	
	//create a buffer to hold the decrypted lines
	char decLine[bytesRead];
	memset(decLine, 0, bytesRead);

	printf("\nBytesRead = %d", bytesRead );
	printf("\nEncrypted line that was read in: %s", 
	       buff2hex((const unsigned char*) lineWrite, bytesRead).c_str());
        
	//decrypt the lines of text
	int decLineSize = RSA_public_decrypt(bytesRead,
					     (const unsigned char*)
					     lineWrite,
					     (unsigned char*)
					     decLine, 
					     rsaPublicKeyVal,
					     RSA_PKCS1_PADDING);    
	//check if there is an error
	if( decLineSize == -1 ){
	  print_errors();
	  exit(-1);
	}

	int bytesWritten = BIO_write(fileWrite, decLine, decLineSize );
	printf("\nbytesWritten = %d", bytesWritten);
	string actualLine = decLine;
	printf("\nPrinting out the DECRYPTED File Text:\n %s", actualLine.c_str());

      }
    
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
