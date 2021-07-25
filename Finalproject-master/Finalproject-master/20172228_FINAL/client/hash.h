#ifndef __HASH_H__
#define __HASH_H__


void digest_message(const unsigned char* message, size_t message_len, unsigned char **digest, unsigned int *digest_len);

#endif
