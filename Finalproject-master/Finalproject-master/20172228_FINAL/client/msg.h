#ifndef __MSG_H__
#define __MSG_H__

#define AES_KEY_128 16
#define BUFSIZE 1024
#include <openssl/aes.h>
enum MSG_TYPE{
	PUBLIC_KEY,
	SECRET_KEY,
	PUBLIC_KEY_REQUEST,
	H_ID_PASSWORD_REQUEST,
	ENCRYPTED_H_ID_PASSWORD,
	IV,
	HASH,
	ERROR,
	ENCRYPTED_KEY,
	ENCRYPTED_MSG,
	LIST_END,
	REGISTER_MSG,
	USER
};

typedef struct _APP_MSG_{
	int type; //type of message: PUBLIC_KEY, SECRET_KEY etc
	unsigned char payload[BUFSIZE + AES_BLOCK_SIZE];	//message(can be KEY, IV, MSG, etc)
	int msg_len;	//length of message
}APP_MSG;

#endif
