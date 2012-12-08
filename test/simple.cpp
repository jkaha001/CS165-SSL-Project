#include <iostream>

#include <openssl/ssl.h>
#include <openssl/bio.h>

using namespace std;

int main(int argc, char *argv[])
{
  //This section uses BIOs to write a copy of infile.txt to outfile.txt
  //  and to send the hash of infile.txt to the command window.
  //  It is a barebones implementation with little to no error checking.
  
  //The SHA1 hash BIO is chained to the input BIO, though it could just
  //  as easily be chained to the output BIO instead.
  
  char infilename[] = "infile.txt";
  char outfilename[] = "outfile.txt";
  
  char buffer[1024];
  
  BIO *binfile, *boutfile, *hash;
  
  //create a BIO stream called binfile, allow it to be read only stream,
  //and load into that stream the infilename file
  binfile = BIO_new_file(infilename, "r"); 
  
  //create a BIO stream called boutfile, specifiy it to be a stream you
  //can write out to, and load the outfilename file to the stream
  boutfile = BIO_new_file(outfilename, "w");
  
  //specify the hash method we will chain to the read/write streams
  hash = BIO_new(BIO_f_md());
  
  //set the hash and SHA1 values to the hash stream
  BIO_set_md(hash, EVP_sha1());
  
  //Chain/Connections of the new i/o streams with hash streams,
  //The Reason we do this is so that whatever is sent through the streams
  //that are chained/connected with the hash stream will always output or
  //read in as a hash value. 
  //value -> hash() -> hashvalue -> inputStream
  //hashValue -> dehash()? -> value -> outputStream
  
  //Chain on the input
  BIO_push(hash, binfile); 
  
  //Chain on the output
  BIO_push(hash, boutfile);
  
  int actualRead, actualWritten;
  cout << "Hello";
  
  //Now we want to read from the hash stream and populate the buffer
  //with whatever was in the hash stream, however we only read in 1024
  //bits of info at a time.  (This is so we optimize our resource no 
  //security improvements from reading the buffer in as chunks)
  while((actualRead = BIO_gets(hash, buffer, 1024)) >= 1)
    {
      //Could send this to multiple chains from here
      //Now we write to the boutfile stream (or file in this case)with 
      //what we just read into the buffer (from the hash stream) in chunks
      actualWritten = BIO_write(boutfile, (const unsigned char*)(buffer),
				actualRead);
    }
  
  //Get digest
  
  //Initialize a buffer that will be filled with information from the 
  //hash stream
  char mdbuf[EVP_MAX_MD_SIZE];
  
  //Now we will read what was in the hash stream and put it into our 
  //mdbuf buffer so we can do stuff with it.
  int mdlen = BIO_gets(hash, mdbuf, EVP_MAX_MD_SIZE);
  
  char buffer0[1024];
  char buffer1[1024];
  
  ////encryption
  
  //create an input stream that will hold the rsaPrivateKey value
  BIO * rsaPrivateKeyInput = BIO_new_file("rsaprivatekey.pem","r");
  
  //load what is in the rsaPrivateKeyInput stream into the RSA defined 
  //object (this will contain S = (phi(n),d) and such)
  RSA * rsaPrivateKeyVal;
  rsaPrivateKeyVal = PEM_read_bio_RSAPrivateKey(rsaPrivateKeyInput, 
						NULL, 0, NULL);
  
  //Now we want to sign whatever is in the mdbuf (which was previously
  //the information we were trying to send to our partner) with the 
  //value of our private key will be using in our RSA. By signing we are
  //creating a new value that will be stored into buffer0, the 
  //RSA_PKCS1_PADDING helps with making it so the hashed value doesn't
  //have the same length as our plain value, and the output is the length
  //of the buffer we wrote to.
  int encryptBufferLength = RSA_private_encrypt(mdlen, 
						(const unsigned char*)
						(mdbuf),
						(unsigned char*)
						buffer0,rsaPrivateKeyVal,
						RSA_PKCS1_PADDING);

  cout << "HELLO";
  
  //just print out the value stored in our buffer for checking purpose
  for(int i = 0; i < mdlen; i++)
    {
      //Print two hexadecimal digits (8 bits or 1 character) at a time
      printf("%02x", mdbuf[i] & 0xFF);
    }
  
  ////decryption
  
  //create an input stream that will hold the rsaPublicKey value
  BIO * rsaPublicKeyInput = BIO_new_file("rsapublickey.pem", "r" );

  //load what is in the rsaPublicKeyInput stream into the RSA defined
  //object (this will contain P = (N,e) and such )
  RSA * rsaPublicKeyVal;
  rsaPublicKeyVal = PEM_read_bio_RSA_PUBKEY(rsaPublicKeyInput, 
					    NULL, 0, NULL);
  
  //
  int decryptBufferLength = RSA_public_decrypt(encryptBufferLength, 
					       (const unsigned char*)
					       (buffer0),
					       (unsigned char*)
					       buffer1, rsaPublicKeyVal,
					       RSA_PKCS1_PADDING);
  
  printf("\n");
  
  BIO_free_all(boutfile);
  BIO_free_all(hash);
  
  return 0;
}


//This function offers an example of chaining a DES cipher to a base 64 encoder
//  to a buffer to a file, using BIOs. Taken almost directly from the example code
//  in the book "Network Security with OpenSSL". The concepts should be useful
//  for preparing the RSA hash and signature.
//  Uncomment the function to try it out.

int write_data(const char *filename, char *out, int len, unsigned char *key)
{
    int total, written;
    BIO *cipher, *b64, *buffer, *file;
    // Create a buffered file BIO for writing
    file = BIO_new_file(filename, "w") ;
    if (! file)
        return 0;
    // Create a buffering filter BIO to buffer writes to the file
    buffer = BIO_new(BIO_f_buffer( ));
    // Create a base64 encoding filter BIO
    b64 = BIO_new(BIO_f_base64( ));
    // Create the cipher filter BIO and set the key.  The last parameter of
    // BIO_set_cipher is 1 for encryption and 0 for decryption
    cipher = BIO_new(BIO_f_cipher( ));
    BIO_set_cipher(cipher, EVP_des_ede3_cbc( ), key, NULL, 1);
    // Assemble the BIO chain to be in the order cipher-b64-buffer-file

    BIO_push(cipher, b64);
    BIO_push(b64, buffer);
    BIO_push(buffer, file);
    // This loop writes the data to the file.  It checks for errors as if the
    // underlying file were non-blocking
    for (total = 0;  total < len;  total += written)
    {
        if ((written = BIO_write(cipher, out + total, len - total) ) <= 0)
        {
            if (BIO_should_retry(cipher) )
            {
                written = 0;
                continue;
            }
            break;
        }
    }
    // Ensure all of our data is pushed all the way to the file
    BIO_flush(cipher) ;
    // We now need to free the BIO chain. A call to BIO_free_all(cipher) would
    // accomplish this, but we' ll first remove b64 from the chain for
    // demonstration purposes.
    BIO_pop(b64) ;
    // At this point the b64 BIO is isolated and the chain is cipher-buffer-file.
    // The following frees all of that memory
    BIO_free(b64) ;
    BIO_free_all(cipher) ;
	return 0;
}
