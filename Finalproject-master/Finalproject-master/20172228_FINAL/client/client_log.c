#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <fcntl.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"
#include "hash.h"

char seps[] = " ";
char* tok;
void token_sep(unsigned char* str, char** arry, int* num);
void file_upload(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv);
void file_download(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv);

void error_handling(char *msg)
{
	fputs(msg, stderr);
	fputs("\n", stderr);
	exit(1);
}


int main(int argc, char *argv[])
{
	/*Setting*/
	int sock;
	struct sockaddr_in serv_addr;
	int len = 0;
	
	APP_MSG msg_in;
	APP_MSG msg_out;
	char plaintext[BUFSIZE + AES_BLOCK_SIZE] = {0x00, };
	char id_password[BUFSIZE + AES_KEY_128] = {0x00, };
	
	unsigned char* digest = NULL;
	unsigned int digest_len=0;
	unsigned char key[AES_KEY_128] = {0x00, };
	unsigned char iv[AES_KEY_128] = {0x00, };
	//unsigned char encrypted_key[BUFSIZE] = {0x00, };
	
	BIO *rpub = NULL;
	RSA *rsa_pubkey = NULL;
	
	int n;
	int plaintext_len;
	int ciphertext_len;
	
	/*generate random key & iv*/
	RAND_poll();
	RAND_bytes(key, sizeof(key));
	RAND_bytes(iv, sizeof(iv));

	/*make a socket*/
	if(argc != 3)
	{
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}
	
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1)
	{
		error_handling("socket() error");
	}
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port=htons(atoi(argv[2]));
	
	/*connect to server*/
	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
	{
		error_handling("connect() error!");
	}
	
	/*setup process*/ //+ send to server a iv
	
	//sending PUBLIC_KEY_REQUEST msg
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = PUBLIC_KEY_REQUEST;
	msg_out.type = htonl(msg_out.type);
	
	/*send to public key request message*/
	n = writen(sock, &msg_out, sizeof(APP_MSG));
	if(n == -1)
	{
		error_handling("writen() error");
	}
	
	//received PUBLIC_KEY msg
	memset(&msg_in, 0, sizeof(msg_out));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	
	//read a message type
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
		
	if(n == -1)//read error
	{
		error_handling("readn() error");
	}
	else if(n == 0)//end to socket
	{
		error_handling("reading EOF");
	}
	
	if(msg_in.type != PUBLIC_KEY)//if not a public key!
	{
		error_handling("message error");
	}
	else //yes public key //+ store in file
	{
		//BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len); //print a public key		
		//connect rpub <=> msg_in
		rpub = BIO_new_mem_buf(msg_in.payload, -1); 
		BIO_write(rpub, msg_in.payload, msg_in.msg_len);
		if(!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL)) //rpub(msg_in-publickey_msg) => rsa_pubkey
		{
			error_handling("PEM_read_bio_RSAPublicKey() error!");
		}
	}
	
	//sending ENCRYPTED KEY (setion key) msg
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = ENCRYPTED_KEY;
	msg_out.type = htonl(msg_out.type);
	msg_out.msg_len = RSA_public_encrypt(sizeof(key), key, msg_out.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING); //encrypt setion key with rsa_publickey
	msg_out.msg_len = htonl(msg_out.msg_len);
	n = writen(sock, &msg_out, sizeof(APP_MSG)); //and sned to server	
	if(n == -1)//if no write
	{
		error_handling("writen() error!");
		
	}
	
	//sending IV msg
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = IV;
	msg_out.type = htonl(msg_out.type);
	msg_out.msg_len = RSA_public_encrypt(sizeof(iv), iv, msg_out.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING); //encrypt setion key with rsa_publickey
	msg_out.msg_len = htonl(msg_out.msg_len);
	n = writen(sock, &msg_out, sizeof(APP_MSG)); //and sned to server	
	if(n == -1)//if no write
	{
		error_handling("writen() error!");
		
	}
	printf("\n*key&iv\n");
	BIO_dump_fp(stdout, (const char*)key, sizeof(key));
	BIO_dump_fp(stdout, (const char*)iv, sizeof(iv));
	
	/****************************Register**************************************/
	
	//reiceve to server a request msg(Id/password!)
	//received ID/Password request msg
	memset(&msg_in, 0, sizeof(msg_in));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
		
	if(n == -1)//read error
	{
		error_handling("readn() error");
	}
	else if(n == 0)//end to socket
	{
		error_handling("reading EOF");
	}
	
	if(msg_in.type != ENCRYPTED_MSG)//if not a id/password request msg!
	{
		error_handling("message error");
	}
	else
	{
		plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext); //regist or complete?
		printf("\n%s\n ", plaintext);
		
	}
	
	if(fgets(plaintext, BUFSIZE+1, stdin) == NULL)
	{
		error_handling("id/password input error!");
	}
	if(!strcmp(plaintext, "q\n") || !strcmp(plaintext, "Q\n"))
	{
		close(sock);
		return 0;
	}
	if(!strcmp(plaintext, "N\n") || !strcmp(plaintext, "n\n"))
	{
		close(sock);
		return 0;
	}	
	len = strlen(plaintext);
	if(plaintext[len-1] == '\n')
	{
		plaintext[len-1] = '\0';
	}
	if(strlen(plaintext) == 0)
	{
		error_handling("id/password input error!");
	}		
	memset(&msg_out, 0, sizeof(msg_out));
	ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload); //ciphertext = 128byte		
	msg_out.msg_len = htonl(ciphertext_len);
	msg_out.type = ENCRYPTED_MSG;
	msg_out.type = htonl(msg_out.type);					
	n = writen(sock, &msg_out, sizeof(APP_MSG));
	if(n == -1)
	{
		error_handling("write() error");
	}
	
	memset(&msg_in, 0, sizeof(msg_in));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
		
	if(n == -1)//read error
	{
		error_handling("readn() error");
	}
	else if(n == 0)//end to socket
	{
		error_handling("reading EOF");
	}	
	if(msg_in.type != ENCRYPTED_MSG)//if not a id/password request msg!
	{
		error_handling("message error");
	}
	else
	{
		plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext); //regist or complete?
		printf("\n%s\n ", plaintext);
		
	}	
	//
	if(fgets(id_password, BUFSIZE+1, stdin) == NULL)
	{
		error_handling("id/password input error!");
	}
	if(!strcmp(id_password, "q\n") || !strcmp(id_password, "Q\n"))
	{
		close(sock);
		return 0;
	}
	len = strlen(id_password);
	if(id_password[len-1] == '\n')
	{
		id_password[len-1] = '\0';
	}
	if(strlen(id_password) == 0)
	{
		error_handling("id/password input error!");
	}
	//H(id password)
	memset(digest, 0, digest_len);
	digest_message((unsigned char*)id_password, len, &digest, &digest_len);		
	memset(&msg_out, 0, sizeof(msg_out));
	ciphertext_len = encrypt((unsigned char*)digest, digest_len, key, iv, msg_out.payload); //ciphertext = 128byte		
	msg_out.msg_len = htonl(ciphertext_len);
	msg_out.type = ENCRYPTED_MSG;
	msg_out.type = htonl(msg_out.type);					
	n = writen(sock, &msg_out, sizeof(APP_MSG));
	if(n == -1)
	{
		error_handling("write() error");
	}
	
	//received
	memset(&msg_in, 0, sizeof(msg_in));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
			
	if(n == -1)//read error
	{
		error_handling("readn() error");
	}
	else if(n == 0)//end to socket
	{
		error_handling("reading EOF");
	}
	if(msg_in.type != ENCRYPTED_MSG)//if not a enc msg!
	{
			error_handling("message error");
	}
	else
	{
		plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
		printf("%s\n", plaintext);
	}

//////////////////////////////////////log-in////////////////////////////////////////////			

	//reiceve to server a request msg(Id/password!)
	//received ID/Password request msg
	memset(&msg_in, 0, sizeof(msg_in));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);		
	if(n == -1)//read error
	{
		error_handling("readn() error");
	}
	else if(n == 0)//end to socket
	{
		error_handling("reading EOF");
	}
	
	if(msg_in.type != H_ID_PASSWORD_REQUEST)//if not a id/password request msg!
	{
		error_handling("message error");
	}
	else //yes id/password request msg
	{
		//compute Id/password
		//input a message that you want to send
		printf("Input a ID and PASSWORD > \n");	
		if(fgets(id_password, BUFSIZE+1, stdin) == NULL)
		{
			error_handling("id/password input error!");
		}
		if(!strcmp(id_password, "q\n") || !strcmp(id_password, "Q\n"))
		{
			close(sock);
			return 0;
		}
		//rmoving '\n' character
		len = strlen(id_password);
		if(id_password[len-1] == '\n')
		{
			id_password[len-1] = '\0';
		}
		if(strlen(id_password) == 0)
		{
			error_handling("id/password input error!");
		}
		//H(id password)
		memset(digest, 0, digest_len);
		digest_message((unsigned char*)id_password, len, &digest, &digest_len);			
		memset(&msg_out, 0, sizeof(msg_out));
		ciphertext_len = encrypt((unsigned char*)digest, digest_len, key, iv, msg_out.payload); //ciphertext = 128byte		
		msg_out.msg_len = htonl(ciphertext_len);
		msg_out.type = ENCRYPTED_H_ID_PASSWORD;
		msg_out.type = htonl(msg_out.type);					
		n = writen(sock, &msg_out, sizeof(APP_MSG));
		if(n == -1)
		{
			error_handling("write() error");
		}
	}
	/*********************************************************************************/	
	//receive msg
	memset(&msg_in, 0, sizeof(msg_out));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	if(n == -1)//read error
	{
		error_handling("readn() error");
	}
	else if(n == 0)//end to socket
	{
		error_handling("reading EOF");
	}
	
	if(msg_in.type != ERROR && msg_in.type != ENCRYPTED_MSG)//if not a H(id/password)!
	{
		error_handling("message error");
	}
	if(msg_in.type == ERROR)	
	{
		close(sock);
		exit(0);
	}
	else if(msg_in.type == ENCRYPTED_MSG)
	{
		msg_in.msg_len = ntohl(msg_in.msg_len);
			
		if(n == -1)//read error
		{
			error_handling("readn() error");
		}
		else if(n == 0)//end to socket
		{
			error_handling("reading EOF");
		}
		if(msg_in.type != ENCRYPTED_MSG)//if not a enc msg!
		{
				error_handling("message error");
		}
		
		plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
		printf("%s\n", plaintext);
			
	}

	//received


////////////////////////////////////////////////////////////////////////////////////////
	/**********************************************************************************************************************/
	
	while(1)
	{
		printf("\n@@I'm routine in@@\n\n");
		//read msg format
		memset(&msg_in, 0, sizeof(msg_out));
		n = readn(sock, &msg_in, sizeof(APP_MSG));
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);
		
		if(n == -1)//read error
		{
			error_handling("readn() error");
		}
		else if(n == 0)//end to socket
		{
			error_handling("reading EOF");
		}
	
		if(msg_in.type != ENCRYPTED_MSG)
		{
			error_handling("message error");
		}
		else
		{
			plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext); //regist or complete?
			printf("\n%s\n ", plaintext);
		}
		
		/*************************************************************************/
		//send
		if(fgets(plaintext, BUFSIZE+1, stdin) == NULL)
		{
			break;
		}
		if(!strcmp(plaintext, "q\n") || !strcmp(plaintext, "Q\n"))
		{
			close(sock);
			exit(0);
		}	
		len = strlen(plaintext);
		if(plaintext[len-1] == '\n')
		{
			plaintext[len-1] = '\0';
		}
		if(strlen(plaintext) == 0)
		{
			break;
		}
		memset(&msg_out, 0, sizeof(msg_out));
		ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload); //ciphertext = 128byte
	
		
		//sending message
		msg_out.msg_len = htonl(ciphertext_len);
		msg_out.type = ENCRYPTED_MSG;
		msg_out.type = htonl(msg_out.type);
		n = writen(sock, &msg_out, sizeof(APP_MSG));
		if(n == -1)
		{
			error_handling("writen() error");
		}
		

		if(strstr(plaintext, "list") != NULL)
		{
			unsigned char* arry[3] = {0x00, };
			int tok_len = 0;
			token_sep(plaintext, arry, &tok_len);
			if(tok_len != 1)
			{
				memset(&msg_in, 0, sizeof(msg_in));
				n = readn(sock, &msg_in, sizeof(APP_MSG));
				msg_in.type = ntohl(msg_in.type);
				msg_in.msg_len = ntohl(msg_in.msg_len);			
				if(msg_in.type != ERROR)//if not a msg
				{
					continue;
				}			
				if(msg_in.type == ERROR)
				{
					plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
					//print the received message
					plaintext[plaintext_len] = '\0';
					printf("\n%s\n", plaintext);
				}
			}
			else
			{			
				while(1)
				{				
					memset(&msg_in, 0, sizeof(msg_in));			
					n = readn(sock, &msg_in, sizeof(APP_MSG));
					msg_in.type = ntohl(msg_in.type);
					msg_in.msg_len = ntohl(msg_in.msg_len);			
					if(msg_in.type != ENCRYPTED_MSG && msg_in.type != LIST_END)//if not a msg
					{
						puts("No message\n");
						close(sock);
					}
					if(msg_in.type == LIST_END)
					{
						break;
					}
					else //yes enc msg
					{
						plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
						//print the received message
						plaintext[plaintext_len] = '\0';
						printf("\n%s\n", plaintext);
					}

				}
			}
		}
		if(strstr(plaintext, "down") != NULL)
		{
			unsigned char* arry[3] = {0x00, };
			int tok_len = 0;
			token_sep(plaintext, arry, &tok_len);
			if(tok_len != 3)
			{
				memset(&msg_in, 0, sizeof(msg_in));
				n = readn(sock, &msg_in, sizeof(APP_MSG));
				msg_in.type = ntohl(msg_in.type);
				msg_in.msg_len = ntohl(msg_in.msg_len);			
				if(msg_in.type != ERROR)//if not a msg
				{
					continue;
				}			
				if(msg_in.type == ERROR)
				{
					plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
					//print the received message
					plaintext[plaintext_len] = '\0';
					printf("\n%s\n", plaintext);
				}
			}
			else
			{			
				file_upload(sock, arry[2], key, iv);
			}
		}

		if(strstr(plaintext, "up") != NULL)
		{
			unsigned char* arry[3] = {0x00, };
			int tok_len = 0;
			token_sep(plaintext, arry, &tok_len);
			if(tok_len != 3)
			{
				memset(&msg_in, 0, sizeof(msg_in));
				n = readn(sock, &msg_in, sizeof(APP_MSG));
				msg_in.type = ntohl(msg_in.type);
				msg_in.msg_len = ntohl(msg_in.msg_len);			
				if(msg_in.type != ERROR)//if not a msg
				{
					continue;
				}			
				if(msg_in.type == ERROR)
				{
					plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
					//print the received message
					plaintext[plaintext_len] = '\0';
					printf("\n%s\n", plaintext);
				}
			}
			else
			{						
				file_download(sock, arry[1], key, iv);
			}
		}
		printf("\n@@end of routine@@\n\n");
	}
	close(sock);
	return 0;
}

void token_sep(unsigned char* str, char** arry, int *num)
{
	int cnt_i = 0;
	tok = strtok((char*)str, seps);
	while (tok != NULL)
	{	
		arry[cnt_i] = tok;
		cnt_i++;
		tok = strtok(NULL, seps);
	}
	*num = cnt_i;
}

void file_upload(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv)
{
	APP_MSG msg_in;
	int fd = 1;
	int n;
	char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };
	int plaintext_len;
	
	printf("\nstore : %s \n", filename);
	fd = open((const char*)filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
	if(fd == -1)
	{
		error_handling("file read error!");
	}
	while(1)
	{
		//receive answer msg
		memset(&msg_in, 0, sizeof(msg_in));
		memset(plaintext, 0, sizeof(plaintext));
		n = readn(sock, &msg_in, sizeof(APP_MSG));	
		//read a message type
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);
				
		if(n == -1)//read error
		{
			error_handling("readn() error");
		}
		if(msg_in.type != ENCRYPTED_MSG && msg_in.type != LIST_END)//if not a msg
		{
				error_handling("message error");
		}
		if(msg_in.type == LIST_END){
			break;
		}
		else //yes msg
		{
			
			plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
			printf("\n%s\n", plaintext);
			if(plaintext_len > 0)
			{
				if(write(fd, plaintext, plaintext_len) != plaintext_len)
				{
					error_handling("write() error");
				}	
			}
			else
			{
				break;
			}
		}

	}
	
	if(fd != -1)
	{
		close(fd);
	}
}

void file_download(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv)
{
	APP_MSG msg_out;
	int fd = 1;
	int n;
	int len;
	int ciphertext_len;
	
	unsigned char buf[BUFSIZE] = {0x00, };
	printf("\ndownload : %s\n", filename);
	memset(&msg_out, 0, sizeof(msg_out));
	fd = open((const char*)filename, O_RDONLY, S_IRWXU);
	
	if(fd == -1)
	{
		error_handling("file read error!");
	}

	while((len = read(fd, buf, sizeof(buf))) > 0)
	{
		if(buf[len-1] == '\n')
		{
			buf[len-1] = '\0';
		}
		printf("\n%s\n", buf);
		ciphertext_len = encrypt((unsigned char*)buf, len, key, iv, msg_out.payload); //ciphertext = 128byte
		msg_out.msg_len = htonl(ciphertext_len);
		msg_out.type = ENCRYPTED_MSG;
		msg_out.type = htonl(msg_out.type);
		n = writen(sock, &msg_out, sizeof(APP_MSG));
	}
	
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = LIST_END;
	msg_out.type = htonl(msg_out.type);	
	n = writen(sock, &msg_out, sizeof(APP_MSG));
	
	if(fd != -1)
	{
		close(fd);
	}
}
