/*
Copyright 2016 Andrew Hodel
	andrewhodel@gmail.com

LICENSE

This program, design, source code, document or sequence of bits is licensed and the terms issued below must be followed.  By using or reading or including this content you are automatically a licensee granted permission by the licensor (Andrew Hodel) under the following terms.

Usage - You may use this content under the following conditions:

	1. Every inclusion of this content within another program, design, source code, document or sequence of bits requires the licensee to notify the licensor via email to the email address andrewhodel@gmail.com.  The message must clearly explain the intended usage, information on the direction of the project to which it is to be included, and the Given Birth Name of the person who is writing the email and using the content as well as the the Company name (if applicable).

	2. This content may only be used in ways which are not commercial and have no commercial outlets.  This means that the content should never be sold or bartered and should never be included with other content which is sold or bartered.  In the case of automated services or products generate from the use of this content, you may use the content to provide services which generate profits; however those services must publish fully their costs and expenses in relation to their income in all forms of currency and or barter in order to use this content to generate profit generating content.  Anyone who is a trade partner in a relation using content generated from this content may notify the Licensor of this agreement of an infrigement of this clause and the Licensor then has a legal right against the Licensee to prosecute in order to demand his payment as well as the publication and the required trade information.

	3. If you wish to use this content in a commercial manner or in a product which may have commercial outlets, you must contact the author to arrange a proper license and proper payment before it's usage.  You may not read the content if your intention is commerce.

	4. You may not use this content and/or the knowledge of this content in any manner of Barter without providing proper compensation to the Owner/Licensor.  This would require written notification to the Licensor with a letter of intention of Barter explaining the terms at which your gain is coming from my work.  From this point equal compensation can be arranged.
*/

// Nexor Encryption

// Assume you have 2 bits, 1 (string) and 1 (key)
// with xor you will get 0 (encrypted string).
// Assume you lose one of the original bits, 1 (string)
// if you xor 1 (key) and 0 (encrypted string)
// you will get the missing value, 1 (string).

// Since all information in a computer is represented as a stream of
// bits, everything is just this or that in series.  There are only a
// few operations you can perform on 2 values which are not known.
// XOR is the only one which has this tri-state ability described
// in the previous paragraph and that is what makes it ideal for
// encryption.  You can read more by studying logic gates.

// This is also true of characters, which are just a set of 8 bits.
// As long as each block is the same length or shorter than the key(s)
// you can xor each bit and gain an encrypted value
// which can then be decrypted later with the key(s).
// That's true private key encryption because without the key
// and the encrypted string you can only guess between 2 values
// for each bit of the data.

// If that were the only case however, messages would be able to be repeated.
// For example, a string aaa may be encrypted to a string bbb and no matter what
// a malicious person could resend bbb to a server and even though the attacker
// doesn't know what bbb actually means the server would act on it as if it was aaa
// because the server has the key(s).

// Take a typical login situation for example.
// Client would connect to the server and send a login string which once encrypted
// has a value of ccc.
// On the next login the client would send the same encrypted string, ccc.
// This means anyone who can listen to the traffic would be able to
// capture (wirejack) and generate a login on the server.  They could repeat
// and entire session for that matter.

// This is stopped by using a random 128 bit block and xor'ing
// it against a set of 128 bit keys, this is the FIRST KEY SET.
// Then the random 128 bit encrypted block is prepended to each message sent across
// the wire and each following block is xor'd by the unencrypted random 128 bit block.

// Then on decryption the decryptor simply decrypts (xor) the first 128 bit block
// with the FIRST KEY SET to gain the original random 128 bit block and then
// uses that along with the SECOND KEY SET on each following block to get the original message.

// an encrypted message looks like this, the 2nd block can repeat for the entire message length:
// [16 bytes - encrypted random block] [16 bytes - encrypted block xor'd by decrypted random block]

// Servers and clients must use the random block for proper security.
// When a socket is opened and for the duration of that socket being open
// each end must store each (validly decrypted) requests random block
// and check that there are no repeated random blocks for the socket session
// to avoid duplicate packets being sent across the wire by a hijacker.

// Servers must also on connection open generate a login hash and send it to the client.
// Then the client must include that login hash when it sends the actual login credentials.
// The server would then have the hash in memory and be able to validate the login request
// which stops it from being repeated.  If someone were to wirejack the login request it would not
// be reusable due to the hash being generated by the server.

// KEY SETS
// Nexor uses 2 key sets, one for the random block and one for the message blocks.
// FIRST KEY SET and SECOND KEY SET each have 128 bit keys (they should be different)
// and there can be as many as you want.  More keys means stronger security
// as the keys are sequentially xor'd against the preceding result for block ^ preceding key.

// TO BUILD
// clang -lm -o nexor nexor.c

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <nexor.h>

// uncomment to print debug output
//#define DEBUG

void printC(char *data, unsigned long len) {
	// seriously, forget '\0'
	unsigned long dd = 0;
	while (1) {
		//printf("%u", data[dd]);
		//printf("%c", data[dd]);
		printf("%02X ", (unsigned)(unsigned char)data[dd]);
		dd++;
		if (dd == len) {
			break;
		}
	}
}

unsigned int nexorOpenKeyfile(FILE *keyfp, char *keys) {

	// get the keyfile size
	fseeko(keyfp, 0, SEEK_END);
	unsigned long int keyfileSize = ftello(keyfp);
	fseeko(keyfp, 0, SEEK_SET);

	if (keyfileSize%16 != 0) {
		printf("keyfile size %lu\n", keyfileSize);
		printf("Keyfile must be divisible by 16 bytes, you probably has a newline in it...\n");
		exit(EXIT_FAILURE);
	}

	if (keyfileSize%32 != 0) {
		printf("Error, number of keys must be equally divisible by 2.\n");
		exit(EXIT_FAILURE);
	}

	unsigned long keyNum = 0;
	int keyChar = 0;
	unsigned long long c = 0;
	char currentChar;
	char tempKey[16];

	while (1) {

		currentChar = fgetc(keyfp);
		keys[c] = currentChar;
		tempKey[keyChar] = currentChar;
		keyChar++;
		c++;

		if (keyChar == 16) {
			#ifdef DEBUG
			printf("added key, ");
			printC(tempKey, 16);
			printf(" | %i\n", keyChar);
			#endif
			keyNum++;
			keyChar = 0;
		}

		if (ftello(keyfp) == keyfileSize) {
			break;
		}

	}

	#ifdef DEBUG
	printf("total keys %u\n", keyNum);
	#endif

	return keyNum;

}

void nexorEncrypt(char *keys, uint32_t keyNum, uint32_t data_in_size, char *datain, char output[]) {
	// output will be 16 bytes larger than the input

	uint32_t c = 0;
	uint32_t p = 0;
	char block[16];
	uint32_t r = 0;
	uint32_t b = 0;

	// /dev/urandom is used to get 16 bytes of cryptographically secure
	// random data... the closer to truly random the better
	char rblock[16];
	FILE *fp;
	fp = fopen("/dev/urandom", "rb");

	// read from urandom 16 bytes
	fread(rblock, 1, 16, fp);
	fclose(fp);

	#ifdef DEBUG
	printf("writing 16 encrypted bytes to file for random block\n");
	#endif
	//printC(rblock, 16);

	// generate encRblock, this is what gets sent across the wire
	// and the other side must have the first half of keys to decrypt the rblock
	// which is then used to decrypt the block with the second half of the keys
	unsigned char encRblock[16];
	c = 0;
	while (c<16) {
		// xor the rblock with FIRST KEY SET
		p = 0;
		while (p < keyNum/2) {
			if (p==0) {
				encRblock[c] = rblock[c] ^ keys[(p*16)+c];
			} else {
				encRblock[c] = encRblock[c] ^ keys[(p*16)+c];
			}
			p++;
		}
		// write it to output
		output[c] = encRblock[c];
		c++;
	}
	#ifdef DEBUG
	printC(rblock, 16);
	printf(" <- rblock\n");
	printC(encRblock, 16);
	printf(" <- encrypted rblock\n");
	#endif

	char enc[16];
	// start counting after the random block which is 16 bytes
	uint32_t n = c;

	while (1) {

		// if the entire file has been encrypted and written, break
		if (n-16 == data_in_size) {
			break;
		}

		block[b] = datain[r];
		// this if is true for each 16 byte step, or block
		if (((r+1)%16 == 0 && r>0) || r+1 == data_in_size) {

			// loop through each character in the block
			c = 0;
			while (c<=b) {
				// xor with SECOND KEY SET

				p = keyNum/2;
				while (p<keyNum) {
					if (p==keyNum/2) {
						enc[c] = block[c] ^ keys[(p*16)+c];
					} else {
						enc[c] = enc[c] ^ keys[(p*16)+c];
					}
					p++;
				}

				// xor it with rblock
				enc[c] = enc[c] ^ rblock[c];
				output[n] = enc[c];
				n++;
				c++;
			}

			#ifdef DEBUG
			printf("wrote block\n");
			#endif

			b = 0;

		} else {
			b++;
		}

		r++;
	}

}

void nexorDecrypt(char *keys, uint32_t keyNum, uint32_t data_in_size, char *datain, char output[]) {
	// output will be 16 bytes smaller than the input

	uint32_t c = 0;
	uint32_t p = 0;
	char block[16];
	uint32_t r = 0;
	uint32_t b = 0;

	char dec[16];
	char rblock[16];

	uint32_t n = 0;
	while (1) {

		if (n == data_in_size-16) {
			// entire file was decrypted and written
			break;
		}

		// read a character from the infile
		block[b] = datain[r];
		if (((r+1)%16 == 0 && r>0) || r+1 == data_in_size) {

			if (r == 15) {
				// this is the first block
				// which on dec means it is the random block
				// get rblock by xor'ing the encrypted rblock with FIRST KEY SET

				c = 0;
				while (c<16) {
					// xor with the first half of the keys
					p = 0;
					while (p < keyNum/2) {
						if (p==0) {
							rblock[c] = block[c] ^ keys[(p*16)+c];
						} else {
							rblock[c] = rblock[c] ^ keys[(p*16)+c];
						}
						p++;
					}
					c++;
				}

				#ifdef DEBUG
				// print the rblock
				printC(block, 16);
				printf(" <- encrypted rblock\n");
				printC(rblock, 16);
				printf(" <- decrypted rblock\n");
				#endif

			} else {
				// loop through each character in the encrypted block

				c = 0;
				while (c<=b) {
					// xor with SECOND KEY SET

					p = keyNum/2;
					while (p<keyNum) {
						if (p==keyNum/2) {
							dec[c] = block[c] ^ keys[(p*16)+c];
						} else {
							dec[c] = dec[c] ^ keys[(p*16)+c];
						}
						p++;
					}
					// xor it with rblock
					dec[c] = dec[c] ^ rblock[c];
					output[n] = dec[c];
					n++;
					c++;
				}

				// print the decrypted block
				//printC(dec, b+1);

			}

			b = 0;

		} else {
			b++;
		}

		r++;
	}
}

int main(int argc, char *argv[]) {
	if (argc == 3 && strncmp(argv[1], "entropy", 7) == 0) {
		FILE *fp;
		fp = fopen(argv[2], "rb");
		unsigned int ch;
		double entropy = 0;
		double p;

		// get the keyfile size
		fseeko(fp, 0, SEEK_END);
		unsigned long int size = ftello(fp);
		fseeko(fp, 0, SEEK_SET);

		printf("\nChecking entropy in %s with file size of %lu bytes.\n", argv[2], size);

		while ((ch = fgetc(fp)) != EOF) {
			p = (float)ch / (float)size;
			if (p > 0) {
				// get base2 log
				entropy = entropy - p*log2f(p);
			}
		}

		fclose(fp);

		printf("Entropy : %f\n\n", entropy);
		printf("The shannon (symbol Sh), also known as a bit, is a unit of information and of entropy defined by IEC 80000-13. One shannon is the information content of an event when the probability of that event occurring is one half. It is also the entropy of a system with two equiprobable states. If a message is made of a sequence of bits, with all possible bit strings equally likely, the message's information content expressed in shannons is equal to the number of bits in the sequence. For this and historical reasons, a shannon is more commonly known as a bit, despite that \"bit\" is also used as a unit of data (or of computer storage, equal to 1/8 of a byte).\n\n1 Sh ≈ 0.693 nat ≈ 0.301 Hart.\n\n");
		exit(EXIT_SUCCESS);
	}

	if (argc == 4 && strncmp(argv[1], "genkey", 6) == 0) {
		// generate keyfile

		if (atol(argv[3])%2 != 0) {
			printf("Error, number of keys to generate must be equally divisible by 2.\n");
			exit(EXIT_FAILURE);
		}

		// /dev/urandom is used to get 16 bytes of cryptographically secure
		// random data... the closer to truly random the better
		char rblock[16];
		FILE *fp;
		fp = fopen("/dev/urandom", "rb");
		FILE *fpw;
		fpw = fopen(argv[2], "wb");

		unsigned int c = 0;
		while (c<atol(argv[3])) {
			// read from urandom 16 bytes
			fread(rblock, 1, 16, fp);
			fwrite(rblock, 1, 16, fpw);
			c++;
		}

		fclose(fp);
		fclose(fpw);

		printf("%lu keys written to %s\n", atol(argv[3]), argv[2]);

		exit(EXIT_SUCCESS);
	}

	if (argc < 5) {
		printf("Encrypt or Decrypt a file:\n");

		printf("\t./nexor TYPE keyfile infile outfile\n\t\tkeyfile is a file containing (128 bit) 16 character keys... the total number of keys must be a multiple of 2\n\t\tTYPE can be either enc or dec\n\t\tinfile and outfile are files for the program io\n");

		printf("\nShow the shannon entropy for a given keyfile:\n");
		printf("\t./nexor entropy keyfile\n\t\tkeyfile is the file containing the keys\n");

		printf("\nGenerate a keyfile from /dev/urandom:\n");
		printf("\t./nexor genkey keyfile numkeys\n\t\tkeyfile is the file to which the keys will be written\n\t\tnumkeys is an integer specifying the total number of keys, it must be equally divisible by 2\n");

		printf("\n\tNote on keyfile: half of the keys are used to encrypt the random message block and the other half are used to encrypt the message itself.  Each key should be a unique 16 characters (or 128 bits).  Use genkey to generate a keyfile.  You can use any level of encryption you want, even millions of bits.  Only use genkey to create real use keyfiles if you trust your machines /dev/urandom.\n");

		printf("\n\tNexor puts no limit on the number of keys (other than your memory).  70,000 128 bit keys is 8,960,000 bit security.\n");

		printf("\n\tDO NOT PUT NEWLINES BETWEEN EACH KEY IN THE KEYFILE, newlines can exist in the keys but they must not be separated by newlines which are an extra character.\n\n");

		printf("** Protip if you are using this to encrypt/decrypt many messages... use a ramdisk for the keyfile, infile and outfile.\n\n");

		exit(EXIT_FAILURE);
	}

	if (strncmp(argv[1], "enc", 3) != 0 && strncmp(argv[1], "dec", 3) != 0) {
		printf("Argument 2 must be enc or dec.\n");
		exit(EXIT_FAILURE);
	}

	// open keyfile
	char *keys;
	FILE *keyfp;
	keyfp = fopen(argv[2], "rb");
	// get the keyfile size
	fseeko(keyfp, 0, SEEK_END);
	uint32_t keyfileSize = ftello(keyfp);
	fseeko(keyfp, 0, SEEK_SET);
	// allocate space for the keys
	keys = malloc(keyfileSize * sizeof(char *));
	if(keys == NULL) {
		fprintf(stderr, "out of memory\n");
		return 0;
	}
	uint32_t keyNum = nexorOpenKeyfile(keyfp, keys);

	// open the infile and outfile
	FILE *infile;
	FILE *outfile;
	infile = fopen(argv[3], "rb");
	outfile = fopen(argv[4], "wb");

	// get the infile size
	fseeko(infile, 0, SEEK_END);
	uint32_t infileSize = ftello(infile);
	#ifdef DEBUG
	printf("infile size %llu\n", infileSize);
	#endif
	fseeko(infile, 0, SEEK_SET);

	// buffer to hold the input and output
	char *output = malloc((infileSize+16)*sizeof(char));
	char *input = malloc(infileSize*sizeof(char));

	uint32_t c = 0;
	while (c<infileSize) {
		input[c] = fgetc(infile);
		c++;
	}

	if (strncmp(argv[1], "enc", 3) == 0) {
		// this is encrypt
		nexorEncrypt(keys, keyNum, infileSize, input, output);
		infileSize += 16;
	} else {
		// this is decrypt
		nexorDecrypt(keys, keyNum, infileSize, input, output);
		infileSize -= 16;
	}

	c = 0;
	// write it to the file, size should be the same with 16 more bytes on encrypt and 16 less on decrypt
	// for the random block
	while (c<infileSize) {
		fputc(output[c], outfile);
		c++;
	}

	free(keys);
	free(output);
	free(input);

	fclose(infile);
	fclose(outfile);

}
