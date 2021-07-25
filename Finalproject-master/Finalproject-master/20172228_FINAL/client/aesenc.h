#ifndef __AESENC_H__
#define __AESENC_H__


int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char *key, unsigned char* iv, unsigned char* ciphertext);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

#endif
