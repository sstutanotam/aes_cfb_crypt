#include <stdlib.h>
#include <string.h>
#include <time.h>

//#include <stdio.h>

// Enable ECB, CTR and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DCTR=1 -DECB=1
//#define CBC 1
//#define CTR 1
//#define ECB 1
//#define CFB 1
//#define AES256 1
//#define AES128 1

#include "aes.h"
#include "modes.h"
#include "sha.h"


int sha384_key_iv(char * in, size_t length, unsigned char * key, unsigned char * iv);
int aes_256_cfb_crypt(const unsigned char *in, unsigned char *out, size_t length, char *strPwd, unsigned char *crypt_iv, int mode);

void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, const AES_KEY *key,
                        unsigned char *ivec, int *num, const int enc)
{

	if (enc)
		CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc, (block128_f)AES_encrypt);
	else
		CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc, (block128_f)AES_encrypt);
}

int randomIV(unsigned char *out)
{
	srand(time(NULL));
	int t_enc_len = 32*sizeof(char);
	char *t_enc = (char *)malloc(t_enc_len);
	int iLen = sizeof(int);
	int _iLen = iLen;
	int t;
	while(_iLen <= t_enc_len)
	{
		t = rand();
		memcpy(t_enc + _iLen - iLen, (char *)&t, iLen);
		_iLen += iLen;
	}

	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	int digest_len = SHA384_DIGEST_LENGTH*sizeof(char);
	unsigned char *digest = malloc(digest_len);
	SHA384_Update(&ctx, t_enc, t_enc_len);
	SHA384_Final(digest, &ctx);
	t = rand() % (digest_len - 16 + 1);
	memcpy(out, digest + t, 16);

	OPENSSL_cleanse(&ctx, sizeof(ctx));
	OPENSSL_cleanse(digest, digest_len);
	free(digest);
	free(t_enc);
	return 16;
}

int randomIv(unsigned char *out)
{
	srand(time(NULL));
	int t_enc_len = 32*sizeof(char);
	char *t_enc = (char *)malloc(t_enc_len);
	int iLen = sizeof(int);
	int _iLen = iLen;
	while(_iLen <= t_enc_len)
	{
		int t = rand();
		/*printf("%s\n", (char *)&t);*/
		memcpy(t_enc + _iLen - iLen, (char *)&t, iLen);
		_iLen += iLen;
	}
	/*
	printf("t_enc = %s\n", t_enc);
	printf("t_enc = %s\n", t_enc + iLen);
	printf("t_enc = %s\n", t_enc + iLen*2);
	printf("t_enc = %s\n", t_enc + iLen*3);
	printf("t_enc = %s\n", t_enc + iLen*4);
	printf("t_enc = %s\n", t_enc + iLen*5);
	printf("t_enc = %s\n", t_enc + iLen*6);
	printf("t_enc = %s\n", t_enc + iLen*7);
	*/

	AES_KEY aesKey;
	int setKey = AES_set_encrypt_key((const unsigned char *)t_enc, 128, &aesKey);
	if(setKey == 0)
	{
		AES_encrypt((const unsigned char *)t_enc + 16, out, &aesKey);
		free(t_enc);
		return 16;
	}
	else
	{
		free(t_enc);
		return 0;
	}
}

int aes_256_cfb_crypt(const unsigned char *in, unsigned char *out, size_t length, char *strPwd, unsigned char *crypt_iv, int mode)
{
	unsigned char *key = (unsigned char *)malloc(32);
	unsigned char *iv = (unsigned char *)malloc(16);
	sha384_key_iv(strPwd, strlen(strPwd), key, iv);
	AES_KEY aesKey;
	int setKey = AES_set_encrypt_key((const unsigned char *)key, 256, &aesKey);
	free(key);
	if (setKey != 0)
	{
		return -1;
	}
	if(mode == 1)
	{
		int num = 0;
		AES_cfb128_encrypt(crypt_iv, out, 16, (const void *)&aesKey, iv, &num, AES_ENCRYPT);
		if(num != 0)
		{
			return -2;
		}
		num = 0;
		AES_cfb128_encrypt(in, out + 16, length, (const void *)&aesKey, crypt_iv, &num, AES_ENCRYPT);
		free(iv);
		/*
		if(num == (length % 16))
		{
			printf("good~\n");
		}
		*/
		return num;
	}
	else if(mode == 2)
	{
		int num = 0;
		AES_cfb128_encrypt(in, crypt_iv, 16, (const void *)&aesKey, iv, &num, AES_DECRYPT);
		if(num != 0)
		{
			return -2;
		}
		num = 0;
		AES_cfb128_encrypt(in + 16, out, length - 16, (const void *)&aesKey, crypt_iv, &num, AES_DECRYPT);
		free(iv);
		return num;
	}
	else if(mode == 3)
	{
		int num = 0;
		AES_cfb128_encrypt(in, out, length, (const void *)&aesKey, crypt_iv, &num, AES_ENCRYPT);
		free(iv);
		return num;
	}
	else if(mode == 4)
	{
		int num = 0;
		AES_cfb128_encrypt(in, out, length, (const void *)&aesKey, crypt_iv, &num, AES_DECRYPT);
		free(iv);
		return num;
	}
	return -3;
}


int sha384_key_iv(char * in, size_t length, unsigned char * key, unsigned char * iv)
{
	SHA512_CTX ctx;
	SHA384_Init(&ctx);
	/*char digest[SHA384_DIGEST_LENGTH] = {0};*/
	int digest_len = SHA384_DIGEST_LENGTH*sizeof(char);
	unsigned char *digest = malloc(digest_len);
	SHA384_Update(&ctx, in, length);
	SHA384_Final(digest, &ctx);
	memcpy(key, digest, 32);
	/*key[32] = '\0';*/
	memcpy(iv, &digest[32], 16);
	/*iv[16] = '\0';*/

	OPENSSL_cleanse(&ctx, sizeof(ctx));
	OPENSSL_cleanse(digest, digest_len);
	free(digest);
	return 32;
}
