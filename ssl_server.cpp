//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
  //-------------------------------------------------------------------------
  // initialize
  SSL_library_init();  
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  
  setbuf(stdout, NULL); // disables buffered output
  
  // Handle commandline arguments
  // Useage: client -server serveraddress -port portnumber filename
  if (argc < 2)
    {
      printf("Useage: server portnumber\n");
      exit(EXIT_FAILURE);
    }
  char* port = argv[1];
  
  printf("------------\n");
  printf("-- SERVER --\n");
  printf("------------\n");
  
  //-------------------------------------------------------------------------
  // 1. Allow for a client to establish an SSL connection
  printf("1. Allowing for client SSL connection...");
  
  // Setup DH object and generate Diffie-Helman Parameters
  DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
  int dh_err;
  DH_check(dh, &dh_err);
  if (dh_err != 0)
    {
      printf("Error during Diffie-Helman parameter generation.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup server context
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  //	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
  SSL_CTX_set_tmp_dh(ctx, dh);
  if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
    {
      printf("Error setting cipher list. Sad christmas...\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the BIO
  BIO* server = BIO_new(BIO_s_accept());
  BIO_set_accept_port(server, port);
  BIO_do_accept(server);
  
  // Setup the SSL
  SSL* ssl = SSL_new(ctx);
  if (!ssl)
    {
      printf("Error creating new SSL object from context.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  SSL_set_accept_state(ssl);
  SSL_set_bio(ssl, server, server);
  if (SSL_accept(ssl) <= 0)
    {
      printf("Error doing SSL_accept(ssl).\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  printf("DONE.\n");
  printf("    (Now listening on port: %s)\n", port);
  
  //-------------------------------------------------------------------------
  // 2. Receive a random number (the challenge) from the client
  printf("2. Waiting for client to connect and send challenge...");
  
  //SSL_read
  string challenge="";
  
  
  int bufflen = 0;
  char buff[BUFFER_SIZE];
  memset(buff, 0, BUFFER_SIZE);
  bufflen = SSL_read(ssl, buff, BUFFER_SIZE);

//   char challengeReadBuff[bufflen];
//   memset(challengeReadBuff, 0, bufflen);
// //   for(int i=0; i < bufflen; i++) 
// //     challengeReadBuff[i] = buff[i];

  printf("    (Challenge: \"%s\")\n", buff2hex((const unsigned char*)buff,bufflen).c_str());
  
  //decrypt the challenge value
  //read the private key text into a stream
  BIO * rsaPrivateKeyInput = BIO_new_file("rsaprivatekey.pem","r");

  //get the parameters for the private key
  RSA * rsaPrivateKeyVal;
  rsaPrivateKeyVal = PEM_read_bio_RSAPrivateKey(rsaPrivateKeyInput, 
						NULL, 0, NULL); 
  //create a new buffer for challenge
  int sizeOfChallenge = bufflen;
  char challengeDecBuff[sizeOfChallenge];
  memset(challengeDecBuff, 0, sizeOfChallenge);

  
  //decrypt the buffer and store the size of the new key
  int challengeDecLen = RSA_private_decrypt(sizeOfChallenge,
					   (const unsigned char*)
					   buff,
					   (unsigned char*)
					   challengeDecBuff, 
					   rsaPrivateKeyVal,
					   RSA_PKCS1_PADDING);  

  if( challengeDecLen == -1 ){
    print_errors();
    printf("SOMETHING WRONG IN PRIVATE DECRYPT");
    exit(-1);
  }

  printf("\nSize of the decrypted challenge %d\n", challengeDecLen);
  printf("\nChallenge after decrypt: %s\n", buff2hex((const unsigned char*)challengeDecBuff,challengeDecLen).c_str());
 
  challenge = challengeDecBuff;
  
  
  printf("DONE.\n");
  printf("    (Challenge: \"%s\")\n", buff2hex((const unsigned char*)
					       challengeDecBuff,
					       challengeDecLen).c_str());
  
  //-------------------------------------------------------------------------
  // 3. Generate the SHA1 hash of the challenge
  printf("3. Generating SHA1 hash...");
  
  //BIO_new(BIO_s_mem());
  //BIO_write
  //BIO_new(BIO_f_md());
  //BIO_set_md;
  //BIO_push;
  //BIO_gets;
  //look in simple.ccp for coments


  char hashString[1024];
  memset(hashString, 0, sizeof(hashString));
  //SHA1 function that John told me about
  // SHA1((const unsigned char*)buff,bufflen,(unsigned char*)buff1);
  
    BIO *binfile, *boutfile, *hash;
    binfile = BIO_new(BIO_s_mem());
    int actualWritten = BIO_write(binfile, buff, bufflen);
  
    hash = BIO_new(BIO_f_md());
    BIO_set_md(hash, EVP_sha1()); 
    BIO_push(hash, binfile);
    
    //int actualWritten = BIO_puts(binfile, buff);
   
    int actualRead = BIO_gets(hash, hashString, 1024);
    // int actualRead;
    
    //  while((actualRead = BIO_gets(hash, buff1, 1024)) >= 1);
    //       {
    // actualWritten = BIO_write(boutfile, (const unsigned char*)(buffer),
    //         //			actualRead);
    //       }
  
  
  int mdlen = actualRead;
  string hash_string = hashString;
  
  printf("SUCCESS.\n");
  printf("    (SHA1 hash: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)hashString,mdlen).c_str(), mdlen);
  
  //-------------------------------------------------------------------------
  // 4. Sign the key using the RSA private key specified in the
  //     file "rsaprivatekey.pem"
  printf("4. Signing the key...");
  
  //PEM_read_bio_RSAPrivateKey
  //RSA_private_encrypt

  //buffer we will be putting the signiture value into
 //  char buffer0[1024];
//   memset(buffer0, 0, sizeof(buffer0));
  
  //create an input stream that will hold the rsaPrivateKey value
  //  BIO * rsaPrivateKeyInput = BIO_new_file("rsaprivatekey.pem","r");

  //load what is in the rsaPrivateKeyInput stream into the RSA defined 
  //object (this will contain S = (phi(n),d) and such)
  //RSA * rsaPrivateKeyParam;
  //rsaPrivateKeyParam = PEM_read_bio_RSAPrivateKey(rsaPrivateKeyInput, 
  //NULL, 0, NULL); 
  //buffer we will be putting the signiture value into
  int sizeOfHashEnc = RSA_size(rsaPrivateKeyVal) - 11; //maybe subtract by ll?
  char hashEncBuff[sizeOfHashEnc];
  memset(hashEncBuff, 0, sizeOfHashEnc);  
  
  //Now we want to sign whatever is in the mdbuf (which was previously
  //the information we were trying to send to our partner) with the 
  //value of our private key will be using in our RSA. By signing we are
  //creating a new value that will be stored into buffer0, the 
  //RSA_PKCS1_PADDING helps with making it so the hashed value doesn't
  //have the same length as our plain value, and the output is the length
  //of the buffer we wrote to.
  int hashEncLen = RSA_private_encrypt(mdlen, 
				       (const unsigned char*)
				       (hashString),
				       (unsigned char*)
				       hashEncBuff,rsaPrivateKeyVal,
				       RSA_PKCS1_PADDING);

  int siglen = hashEncLen;
  char* signature=hashEncBuff;  
  


//   //FOR TESTING PURPOSES///////////////////////////////////////////////////////

//   BIO * rsaPublicKeyInput = BIO_new_file("rsapublickey.pem", "r" );
  
//   RSA * rsaPublicKeyVal;
//   rsaPublicKeyVal = PEM_read_bio_RSA_PUBKEY(rsaPublicKeyInput, 
// 					    NULL, 0, NULL);
  
//   int sizeOfBuff = encryptBufferLength;
//   char decryptSign[sizeOfBuff];
//   memset(decryptSign, 0, sizeOfBuff);
  
//   int decryptBufferLength = RSA_public_decrypt(sizeOfBuff,
// 					       (const unsigned char*)
// 					       buffer0,
// 					       (unsigned char*)
// 					       decryptSign, 
// 					       rsaPublicKeyVal,
// 					       RSA_PKCS1_PADDING);

//   string testing = decryptSign; 

//   printf("    (TESTING: Signed key length: %d bytes)\n", siglen);
//   printf("    (TESTING:Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);
  
//   printf("\nTESTING:Size of decrypted Value = %d!!!", decryptBufferLength);
//   printf("\nTESTING:Printing decrypted value %s\n", buff2hex((const unsigned char*)decryptSign, decryptBufferLength).c_str());

//   ///////////////////////////////////////////////////////////////////////////
  
  printf("DONE.\n");
  printf("    (Signed key length: %d bytes)\n", siglen);
  printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)hashEncBuff, hashEncLen).c_str(), siglen);
  
  //-------------------------------------------------------------------------
  // 5. Send the signature to the client for authentication
  printf("5. Sending signature to client for authentication...");
  
  //BIO_flush
  //SSL_write

  int hashEncLenSend = SSL_write(ssl, hashEncBuff, siglen);
  int testFlush = BIO_flush(server);
  if( testFlush == -1 || testFlush == 0 )
    {
      printf("SOMETHING WENT WRONG WHEN FLUSHING\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  printf("DONE.\n");
  
  //-------------------------------------------------------------------------
  // 6. Receive a filename request from the client
  printf("6. Receiving file request from client...");
  
  //SSL_read
  int fileNameSize = BUFFER_SIZE;
  char fileNameRecieved[fileNameSize];
  memset(fileNameRecieved, 0, fileNameSize);
  fileNameSize = SSL_read(ssl, fileNameRecieved, fileNameSize);
  // printf("filenamesize = %d", fileNameSize);
  
  printf("RECEIVED.\n");
  printf("    (File requested: \"%s\"\n", buff2hex((const unsigned char*)fileNameRecieved, fileNameSize).c_str());
  
  //-------------------------------------------------------------------------
  // 7. Send the requested file back to the client (if it exists)
  printf("7. Attempting to send requested file to client...");
  
  PAUSE(2);
  //BIO_flush
  //BIO_new_file
  //BIO_puts(server, "fnf");
  //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
  //SSL_write(ssl, buffer, bytesRead);
  
  int bytesSent=0;
  
  printf("SENT.\n");
  printf("    (Bytes sent: %d)\n", bytesSent);
  
  //-------------------------------------------------------------------------
  // 8. Close the connection
  printf("8. Closing connection...");
  
  //SSL_shutdown
  SSL_shutdown(ssl);
  //BIO_reset
  printf("DONE.\n");
  
  printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
  
  //-------------------------------------------------------------------------
  // Freedom!
  print_errors();
  BIO_free_all(server);
  return EXIT_SUCCESS;
}
