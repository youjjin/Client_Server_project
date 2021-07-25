#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <dirent.h> //directory name list
#include <fcntl.h>

#include <signal.h>
#include <sys/wait.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/conf.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"
#include "hash.h"

#define SHA256_SIZE 32

char seps[] = " ";
char* tok;
void token_sep(unsigned char* str, char** arry, int* num);
void file_upload(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv);
void file_download(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv);
void dirfile_list(int sock, struct dirent **namelist, unsigned char *key, unsigned char *iv);

const char *path = "."; 

void error_handling(char *msg)
{
	fputs(msg, stderr);
	fputs("\n", stderr);
	exit(1);
}
void RSA_key_generator()
{
	BIO *bp_public = NULL, *bp_private = NULL;

	/*key_generator(private_key, public_key)*/
	unsigned long e_value = RSA_F4;
	BIGNUM *exponent_e = BN_new();
	int ret = 1;
	RSA *rsa;
	rsa = RSA_new();
	
	BN_set_word(exponent_e, e_value);
	
	if(RSA_generate_key_ex(rsa, 2048, exponent_e, NULL) == 0)
	{
		fprintf(stderr, "RSA_generate_key_ex() error\n");
	}  
	
	bp_public = BIO_new_file("public.pem", "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
	if(ret != 1)
	{
		goto err;
	}
	
	bp_private = BIO_new_file("private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);	
	if(ret != 1)
	{
		ret = -1;
		goto err;
	}
	
err:
	RSA_free(rsa);
	BIO_free_all(bp_public);
	BIO_free_all(bp_private);

}

void read_childproc(int sig)
{
	pid_t pid;
	int status;
	pid = waitpid(-1, &status, WNOHANG);
	printf("removed proc id : %d\n", pid);
}

int main(int argc, char *argv[])
{

	/*setting*/
	//RSA_key_generator();
	//process setting
	pid_t pid;
	struct sigaction act;
	int state;
	
	act.sa_handler = read_childproc;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	state = sigaction(SIGCHLD, &act, 0);
	
	
	//socket setting	
	int serv_sock = -1;
	int clnt_sock = -1;
	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size;
	
	//AES setting
	APP_MSG msg_in;
	APP_MSG msg_out;
	char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };
	unsigned char total_list[BUFSIZE+AES_BLOCK_SIZE+SHA256_SIZE] = {0x00, };
	
	int n;
	int len;
	int plaintext_len;
	int ciphertext_len;
	int publickey_len;
	int encryptedkey_len;
	int h_id_password_len;
		
	unsigned char* digest = NULL;
	unsigned int digest_len=0;
	
	//RSA setting
	unsigned char key[AES_KEY_128] = {0x00, };
	unsigned char h_id_password[BUFSIZE+AES_KEY_128] = {0x00, };
	unsigned char iv[AES_KEY_128] = {0x00, };
	unsigned char buffer[BUFSIZE] = {0x00, };
	BIO *bp_public = NULL, *bp_private = NULL;
	BIO *pub = NULL;
	RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;
	
	/*make a server socket*/
	if(argc != 2)
	{
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

	serv_sock = socket(PF_INET, SOCK_STREAM, 0);

	if(serv_sock == -1)
	{
		error_handling("socket() error");
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

	if(bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
	{
		error_handling("bind() error");
	} 

	if(listen(serv_sock, 5) == -1)
	{
		error_handling("listen() error");
	}
	//reading public key
	bp_public = BIO_new_file("public.pem", "r");
	if(!PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL))
	{
		printf("public key read error!\n");
		close(serv_sock);
		return 0;
	}
	
	//reading private key 
	bp_private = BIO_new_file("private.pem", "r");
	if(!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL))
	{
		printf("private key read error!\n");
		close(serv_sock);
		return 0;
	}

	while(1)
	{
		clnt_addr_size = sizeof(clnt_addr);
		clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
		if(clnt_sock == -1)
		{
			continue;
		}
		else
		{
			printf("\n[TCP Server] Client conncected: IP=%s, port=%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
			puts("new client connected...");
		}
		pid = fork();
		if(pid == -1)
		{
			close(clnt_sock);
			continue;
		}
		if(pid == 0)
		{
			close(serv_sock);
			
			//setup process
			memset(&msg_in, 0, sizeof(msg_out));
			n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
			msg_in.type = ntohl(msg_in.type);
			msg_in.msg_len = ntohl(msg_in.msg_len);
			if(n == -1)
			{
				close(clnt_sock);
				puts("readn() error");
			}
			else if(n == 0)
			{
				close(clnt_sock);
				puts("reading EOF");
			}
			if(msg_in.type != PUBLIC_KEY_REQUEST)
			{
				close(clnt_sock);
				puts("message error");
			}
			else //if this is public key requst message
			{
				//sending PUBLIC_KEY
				memset(&msg_out, 0, sizeof(msg_out));
				msg_out.type = PUBLIC_KEY;
				msg_out.type = htonl(msg_out.type);
					
				pub = BIO_new(BIO_s_mem());
				PEM_write_bio_RSAPublicKey(pub, rsa_pubkey);
				publickey_len = BIO_pending(pub);
					
				BIO_read(pub, msg_out.payload, publickey_len);
				msg_out.msg_len = htonl(publickey_len);
				n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
				if(n == -1)
				{
					close(clnt_sock);
					puts("writen() error!");
				}
			}
			
			/*receive a encrypted setionkey*/
			memset(&msg_in, 0, sizeof(msg_out));
			n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
			msg_in.type = ntohl(msg_in.type);
			msg_in.msg_len = ntohl(msg_in.msg_len);
				
			if(msg_in.type != ENCRYPTED_KEY)
			{
				close(clnt_sock);
				puts("message error!");
			}
			else
			{
				encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
				memcpy(key, buffer, encryptedkey_len);
			}
				
			/*receive a IV*/
			memset(&msg_in, 0, sizeof(msg_out));
			memset(&buffer, 0, sizeof(buffer)); //this buffer? &buffer?
			n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
			msg_in.type = ntohl(msg_in.type);
			msg_in.msg_len = ntohl(msg_in.msg_len);
				
			if(msg_in.type != IV)
			{
				close(clnt_sock);
				puts("message error!");
			}
			else
			{
				encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
				memcpy(iv, buffer, encryptedkey_len);
			}
				
			printf("\n*key&iv\n");
			BIO_dump_fp(stdout, (const char*)key, sizeof(key));
			BIO_dump_fp(stdout, (const char*)iv, sizeof(iv));	
			
			/*********************************************Register**********************************************************/	
			FILE* fp = NULL;
			unsigned char regist_msg[] = "Do you want to register?(Yes : Y or y / No : N or n)";
			unsigned char req_log_msg[] = "Input your register ID Passwrod! >";
			memset(&msg_out, 0, sizeof(msg_out));
			//send ask msg
			msg_out.type = ENCRYPTED_MSG;
			msg_out.type = htonl(msg_out.type);
			ciphertext_len = encrypt((unsigned char*)regist_msg, sizeof(regist_msg), key, iv, msg_out.payload);
			msg_out.msg_len = htonl(ciphertext_len);
			n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
			if(n == -1)
			{
				close(clnt_sock);
				puts("write() error");
			}
					
			//receive answer msg
			memset(&msg_in, 0, sizeof(msg_in));
			n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));	
			//read a message type
			msg_in.type = ntohl(msg_in.type);
			msg_in.msg_len = ntohl(msg_in.msg_len);
					
			if(n == -1)//read error
			{
				close(clnt_sock);
				puts("readn() error");
			}
			else if(n == 0)//end to socket
			{
				close(clnt_sock);
				puts("no message");
			}
					
			if(msg_in.type != ENCRYPTED_MSG)//if not a msg
			{
				close(clnt_sock);
				puts("message error");
			}
			else //yes msg
			{
				plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
				if(!strcmp(plaintext, "Y") || !strcmp(plaintext, "y"))
				{						
					memset(&msg_out, 0, sizeof(msg_out));
					msg_out.type = ENCRYPTED_MSG;
					msg_out.type = htonl(msg_out.type);
					ciphertext_len = encrypt((unsigned char*)req_log_msg, sizeof(req_log_msg), key, iv, msg_out.payload);
					msg_out.msg_len = htonl(ciphertext_len);
					n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
					if(n == -1)
					{
						close(clnt_sock);
						puts("write() error");
					}
												
					memset(&msg_in, 0, sizeof(msg_in));
					n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));		
					if(n == -1)
					{
						close(clnt_sock);
						puts("readn() error");
						break;
					}
					else if(n == 0)
					{
						close(clnt_sock);
						puts("read end!");
						break;
					}
					msg_in.type = ntohl(msg_in.type);
					msg_in.msg_len = ntohl(msg_in.msg_len);
					plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
					////////////////////////////////////////////////////////						
					//regist
					fp = fopen("my_user.txt", "ab");
					fputs((const char*)plaintext, fp);
					fputs("\n", fp);
					fclose(fp);	
					
					unsigned char msg1[] = "Congraturation@@\nNow, You are a user for this site!\n";
					memset(&msg_out, 0, sizeof(msg_out));		
					msg_out.type = ENCRYPTED_MSG;
					msg_out.type = htonl(msg_out.type);							
					ciphertext_len = encrypt((unsigned char*)msg1, sizeof(msg1), key, iv, msg_out.payload);
					msg_out.msg_len = htonl(ciphertext_len);
					n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
					if(n == -1)
					{
						close(clnt_sock);
						puts("write() error");
					}			
				}
				
			}
///////////////////////////////////login///////////////////////////////////////////
			//send to server a request msg(Id/password!)
			memset(&msg_out, 0, sizeof(msg_out));
			msg_out.type = H_ID_PASSWORD_REQUEST;
			msg_out.type = htonl(msg_out.type);
			n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
			if(n == -1)
			{
				close(clnt_sock);
				puts("written() error");
			}

			memset(&msg_in, 0, sizeof(msg_in));
			n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
			//read a message type
			msg_in.type = ntohl(msg_in.type);
			msg_in.msg_len = ntohl(msg_in.msg_len);				
			if(n == -1)//read error
			{
				close(clnt_sock);
				puts("readn() error");
			}
			else if(n == 0)//end to socket
			{
				close(clnt_sock);
				puts("reading EOF");
			}
			if(msg_in.type != ENCRYPTED_H_ID_PASSWORD)//if not a id/password!
			{
				close(clnt_sock);
				puts("message error");
			}
			else //yes id/password
			{
				h_id_password_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)h_id_password);
				printf("I recieved id/password\n");
			}
			
			/*********************************************************************************/	
			
			//1)find my_user folder
			fp = fopen("my_user.txt", "rb");
			assert(fp != NULL);
				
			unsigned char buff[BUFSIZE] = {0x00, };
			unsigned char flag = 0; //yes = 1/ no = 0
				
			while(fgets((char*)buff, sizeof(buff), fp) != NULL)
			{
				//2)find user hash
				if(strstr(buff, h_id_password) != NULL)
				{
					//3)yes? next step
					flag = 1;
					break;
				}
				 memset(buff, 0, sizeof(buff));
			}
			
			if(flag == 0)
			{
				memset(&msg_out, 0, sizeof(msg_out));		
				//send ask msg
				msg_out.type = ERROR;
				msg_out.type = htonl(msg_out.type);												
				//sending the inputed ask message
				n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
				if(n == -1)
				{
					puts("write() error");
				}
	
			}
			else{
				unsigned char msg1[] = "You are an authorized user\n";
				memset(&msg_out, 0, sizeof(msg_out));		
				//send ask msg
				msg_out.type = ENCRYPTED_MSG;
				msg_out.type = htonl(msg_out.type);
						
				ciphertext_len = encrypt((unsigned char*)msg1, sizeof(msg1), key, iv, msg_out.payload);
				msg_out.msg_len = htonl(ciphertext_len);
							
				//sending the inputed ask message
				n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
				if(n == -1)
				{
					close(clnt_sock);
					puts("write() error");
				}
			}
/////////////////////////////////////////////////////////////////////////////////////
			//send service msg
			unsigned char ask_msg[] = "What kind of service do you want?\n1)list (output current directory list)\n2)down filename1 filename2 (download filename1 from the server and save it as filename2)\n3)up filename1 filename2 (upload filename1d to filename2)\n Input your order(If you compute 'q' or 'Q', then service is end) >";	
			unsigned char err_msg[] = "Not a command!";
			while(1)
			{	printf("\n@@I'm routine in@@\n\n");
				//send msg format
				memset(&msg_out, 0, sizeof(msg_out));
				msg_out.type = ENCRYPTED_MSG;
				msg_out.type = htonl(msg_out.type);	
				ciphertext_len = encrypt((unsigned char*)ask_msg, sizeof(ask_msg), key, iv, msg_out.payload);
				msg_out.msg_len = htonl(ciphertext_len);
				n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
				if(n == -1)
				{
					close(clnt_sock);
					puts("write() error");
				}
				
				/*read*/
				memset(&msg_in, 0, sizeof(msg_in));
				n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));		
				if(n == -1)
				{
					close(clnt_sock);
					puts("readn() error");
					break;
				}
				else if(n == 0)
				{
					close(clnt_sock);
					puts("read end!");
					break;
				}
				msg_in.type = ntohl(msg_in.type);
				msg_in.msg_len = ntohl(msg_in.msg_len);
				plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);
				printf("%s \n", plaintext);
				
				//if receive msg "list"
				if(strstr(plaintext, "list") != NULL)
				{
					unsigned char* arry[3] = {0x00, };
					int tok_len = 0;
					token_sep(plaintext, arry, &tok_len);
					if(tok_len != 1)
					{
						memset(&msg_out, 0, sizeof(msg_out));
						msg_out.type = ERROR;
						msg_out.type = htonl(msg_out.type);	
						ciphertext_len = encrypt((unsigned char*)err_msg, sizeof(err_msg), key, iv, msg_out.payload);
						msg_out.msg_len = htonl(ciphertext_len);
						n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
						if(n == -1)
						{
							close(clnt_sock);
							puts("write() error");
						}
					}
					else
					{
						struct dirent ** dirlist = NULL;		
						dirfile_list(clnt_sock, dirlist, key, iv);
						free(dirlist);
					}

				}
			
				//if receive msg "down filename1 filename2"
				if(strstr(plaintext, "down") != NULL)
				{
					unsigned char* arry[3] = {0x00, };
					int tok_len = 0;
					token_sep(plaintext, arry, &tok_len);
					if(tok_len != 3)
					{
						memset(&msg_out, 0, sizeof(msg_out));
						msg_out.type = ERROR;
						msg_out.type = htonl(msg_out.type);	
						ciphertext_len = encrypt((unsigned char*)err_msg, sizeof(err_msg), key, iv, msg_out.payload);
						msg_out.msg_len = htonl(ciphertext_len);
						n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
						if(n == -1)
						{
							close(clnt_sock);
							puts("write() error");
						}
					}
					else
					{
						file_download(clnt_sock, arry[1], key, iv);
					}

				}
				//if receive msg "up filename1 filename2"
				if(strstr(plaintext, "up") != NULL)
				{
					unsigned char* arry[3] = {0x00, };
					int tok_len = 0;
					token_sep(plaintext, arry, &tok_len);					
					if(tok_len != 3)
					{
						memset(&msg_out, 0, sizeof(msg_out));
						msg_out.type = ERROR;
						msg_out.type = htonl(msg_out.type);	
						ciphertext_len = encrypt((unsigned char*)err_msg, sizeof(err_msg), key, iv, msg_out.payload);
						msg_out.msg_len = htonl(ciphertext_len);
						n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
						if(n == -1)
						{
							close(clnt_sock);
							puts("write() error");
						}
					}
					else
					{
						token_sep(plaintext, arry, tok_len);
						file_upload(clnt_sock, arry[2], key, iv);
					}
				}
				
				printf("\n@@end of routine@@\n\n");
			}	
			
			close(clnt_sock);
			printf("\n[TCP Server] Client close: IP=%s, port=%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
		}
		else
		{
			close(clnt_sock);
		}
	}
}

void file_upload(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv)
{
	APP_MSG msg_in;
	int fd = 1;
	int n;
	char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };
	int plaintext_len;
	
	printf("store : %s \n", filename);
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
			printf("%s\n", plaintext);
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


void token_sep(unsigned char* str, char** arry, int* num)
{
	int cnt_i = 0;
	tok = strtok((char*)str, seps);
	while (tok != NULL)
	{	
		arry[cnt_i] = tok;
		cnt_i++;
		tok = strtok(NULL, seps);
	}
	printf("cnt_i : %d\n", cnt_i);
	*num = cnt_i;
}


void file_download(int sock, unsigned char* filename, unsigned char* key, unsigned char* iv)
{
	APP_MSG msg_out;
	int fd = 1;
	int n;
	int len;
	int ciphertext_len;
	
	unsigned char buf[BUFSIZE] = {0x00, };
	printf("download : %s\n", filename);
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
		
		printf("%s", buf);
		ciphertext_len = encrypt((unsigned char*)buf, len, key, iv, msg_out.payload); //ciphertext = 128byte
		msg_out.msg_len = htonl(ciphertext_len);
		msg_out.type = ENCRYPTED_MSG;
		msg_out.type = htonl(msg_out.type);
		n=writen(sock, &msg_out, sizeof(APP_MSG));	
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

void dirfile_list(int sock, struct dirent **namelist, unsigned char *key, unsigned char *iv)
{
	int clnt_sock = sock;
	int count; 
	int idx; 
	int n;
	int len;
	APP_MSG msg_out;	
	int ciphertext_len;
	if((count = scandir(path, &namelist, NULL, alphasort)) == -1) 
	{ 
		error_handling("list error!\n"); 
	}
	
	for(idx = count - 1; idx >= 0; idx--) 
	{

		 memset(&msg_out, 0, sizeof(msg_out));
		 len = strlen(namelist[idx]->d_name);
		 msg_out.type = ENCRYPTED_MSG;
		 msg_out.type = htonl(msg_out.type);	
  		 ciphertext_len = encrypt((unsigned char*)namelist[idx]->d_name, len, key, iv, msg_out.payload);
		 msg_out.msg_len = htonl(ciphertext_len);
		 n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
		 if(n == -1)
		 {
			 error_handling("write() error");
		 }				
	}
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = LIST_END;
	msg_out.type = htonl(msg_out.type);	
	n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
	
	// 건별 데이터 메모리 해제 
	for(idx = 0; idx < count; idx++) 
	{
		 free(namelist[idx]); 
	} 			 
}

