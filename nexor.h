#ifndef NEXOR_H_
#define NEXOR_H_

void printC(char *data, unsigned long len);
unsigned int nexorOpenKeyfile(FILE *keyfp, char *keys);
void nexorEncrypt(char *keys, uint32_t keyNum, uint32_t data_in_size, char *datain, char output[]);
void nexorDecrypt(char *keys, uint32_t keyNum, uint32_t data_in_size, char *datain, char output[]);

#endif
