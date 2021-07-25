#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

void handle_Errors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

void digest_message(const unsigned char* message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;
	if((mdctx = EVP_MD_CTX_create()) == NULL)
	{
		handle_Errors();
	}
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
	{
		handle_Errors();
	}
	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
	{
		handle_Errors();
	}
	if((*digest = (unsigned char*)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
	{
		handle_Errors();
	}
	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
	{
		handle_Errors();
	}
	
	EVP_MD_CTX_destroy(mdctx);
}
