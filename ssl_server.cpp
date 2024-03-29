//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <fstream>
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
  
  //read what writen from the client
  bufflen = SSL_read(ssl, buff, BUFFER_SIZE);

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
  
  BIO *binfile, *boutfile, *hash;
  //create a new bio stream
  binfile = BIO_new(BIO_s_mem());
  
  //
  int actualWritten = BIO_write(binfile, buff, bufflen);
  
  hash = BIO_new(BIO_f_md());
  BIO_set_md(hash, EVP_sha1()); 
  BIO_push(hash, binfile);
  
  int actualRead = BIO_gets(hash, hashString, 1024);
  
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

  //load what is in the rsaPrivateKeyInput stream into the RSA defined 
  //object (this will contain S = (phi(n),d) and such)
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
				       hashEncBuff,
				       rsaPrivateKeyVal,
				       RSA_PKCS1_PADDING);

  int siglen = hashEncLen;
  char* signature=hashEncBuff;  
  
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

  //create a new buffer to store the decrypted file name
  int sizeOfDecFileName = fileNameSize;
  char decFileName[sizeOfDecFileName];
  memset(decFileName, 0, sizeOfDecFileName);
    
  //decrypt the buffer and store the size of the new key
  sizeOfDecFileName = RSA_private_decrypt(fileNameSize,
					  (const unsigned char*)
					  fileNameRecieved,
					  (unsigned char*)
					  decFileName, 
					  rsaPrivateKeyVal,
					  RSA_PKCS1_PADDING);

  string actualFileName = decFileName;
  
  printf("RECEIVED.\n");
  printf("    (File requested encrypted value is: \"%s\"\n", buff2hex((const unsigned char*)fileNameRecieved, fileNameSize).c_str());
  printf("    (File requested's actual value: \"%s\"\n", buff2hex((const unsigned char*)decFileName, sizeOfDecFileName).c_str());
  printf("    (File requested: \"%s\"\n", actualFileName.c_str());
  
  //-------------------------------------------------------------------------
  // 7. Send the requested file back to the client (if it exists)
  printf("7. Attempting to send requested file to client...");
  
  PAUSE(2);
  //BIO_flush
  //BIO_new_file
  //BIO_puts(server, "fnf");
  //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
  //SSL_write(ssl, buffer, bytesRead);

  int bytesSent = 0;

  //create a BIO stream and store the file the client wanted onto it
  BIO * fileRead = BIO_new_file(actualFileName.c_str(), "r");
  
  //split and encrypt the file in chunks
  int bytesRead = 1;
  while( bytesRead > 0 )
    { 
      //create a buffer to store the actual text 
      int maxLineSize = RSA_size(rsaPrivateKeyVal) - 11;
      char lineRead[maxLineSize];
      memset(lineRead, 0, maxLineSize);
     
      //store what is in the file to the newly created buffer,
      //also record how many bytes were read in
      bytesRead = BIO_gets(fileRead, lineRead, maxLineSize);
     
      //create a buffer to hold the lines of text after we have properly
      //encrypted the lines (the size of the buffer is equal to the bytesRead
      char encLine[bytesRead];
      memset(encLine, 0, bytesRead);
     
     printf("\nPrinting out BytesRead = %d", bytesRead);
     printf("\nPrinting out the File Text:\n %s", lineRead);
     
     //encrypt the line and store it into the encLine buffer
     //take note how many bits were stored
     int encLineSize = RSA_private_encrypt(bytesRead, 
					   (const unsigned char*)
					   (lineRead),
					   (unsigned char*)
					   encLine,
					   rsaPrivateKeyVal,
					   RSA_PKCS1_PADDING);
     
     //check if there is an error
     if( encLineSize == -1 ){
	  print_errors();
	  exit(-1);
     }
   
     printf("\nPrinting out the ENCRYPTED File Text:\n %s", 
	    buff2hex((const unsigned char*)encLine, encLineSize).c_str());
     
     //write to the client and take note how many bytes were sent
     int temp = SSL_write(ssl, encLine, encLineSize);
     BIO_flush(server);
     bytesSent += temp;
    
   }
  
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
