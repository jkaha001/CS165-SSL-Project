------------------------------------------------------------------------
Justin Kahal
README FOR PROJECT CS165 OPENSSL
github account: https://github.com/jkaha001/CS165-SSL-Project.git
------------------------------------------------------------------------
HOW TO RUN:
open up two terminals and have each one say the following:
server localhost:1234 Kahal.txt
client localhost:1234 Kahal.txt

Make sure that there is the Kahal.txt file in the folder you are running 
the program in.

Also make sure that you type "make" before you run the program so that it
compiles and creates the server and client executables.
------------------------------------------------------------------------
HOW IT WORKS:
-The client will initally create a random "challenge" number using the ssl
library.
-The client will then encrypt that random value using RSA public encrypt 
and send the encrypted value over to the server. (using SSL_write())
-The server will then read the clients random number (using SSL_read())
and then decrypt that value using RSA private decrypt
-Once the server has decrypted the random number it will hash the number
into another ambiguos number.
-Once the number has been hashed the server will encrypted the hash value
using the RSA private encrypt function and then send that number over to
the client.
-The client should then recieve the encrypted hash value, it should then
decrypt this value using RSA public decrypt.
-At the same time the client will also hash the original "challenge" value
on the client side.  This was the whole point of hashing the value on the
server side as well because once we decrypt what the server sent the client
and we decrypt it, the value of the decrpyt number should be the same as the
value the client hashes on its side.  If these values are not equal then the
server is not who it says it is and an authentication failed message should
show.
-If all goes well and the hashed value the client creates and the decrypted 
hash value that the client got from the server match up then that means the
client has established that the server is who it say it is. 
-At this point the client will send over a file name to the server that the
server is said to have, it must of course encrypt the file name before sending
the request over to the server to ensure security.
-The server will then recieve the encrypted file name that was requested by
the client, at this point the server must decrypt the file name.
-Once the server knows which file the client is looking for, it will store the
file (if it has it) in a BIO stream so that it can start feeding information to
the client.
-In order to ensure security and maximize resource the server will start 
retrieving chunks of information (of fixed size) from the stream while at
the same time encrypting this information.
-For every chuck of information taken out and encrypted, the server will send
out (using SSL_write) the chunks to the client.  It will do this untill all 
information in the file has been seen.
-On the client side, it will be recieving this information chunk by chunk but
as encrypted information.  The client must of course decrypt each chunk of 
information as it is coming in.
-While the client is decrypting each chunk it will also print out to terminal
what the encrypted value was and what its decrypted value is, it will also
print all the decrypted value into a file called outputFile.txt (THIS IS WHERE
MY OUTPUT WILL BE RESIDING)
-Once all information has been retrieved from the server, and decrypted, the
program should terminate using ssl_shutdown() on both the client and server.
-------------------------------------------------------------------------------
PROBLEMS THAT THE PROGRAM HAS:
-Even though my hash function seems to be right, I was told by a fellow colleage
that my hash function outputs the same thing no matter what value I am hashing.
Apparently the reason for this is because I am hashing a random value found in
a space of memory each time I call hash... So no matter what the random value,
the hash value will always be the same. THIS IS A TODO ON MY PART.

-No error checking for many of the functions that may have errors.

-Biggest problem I had with this project was the hashing and the using the 
RSA_private/public_decrypt() function.  The size of the buffer that I am 
trying to decrypt to was always off by a certain amount so I had to tediously
figure the problem out.

-All in all my program should work fine decrypting and encrypting values from
and to the client and server, if there are any problems I failed to see please
tell me.

-The github account that I used for this project is:
 https://github.com/jkaha001/CS165-SSL-Project.git
not the other one that I submitted to you earlier this quarter.
