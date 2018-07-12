#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>


#include "aes_cfb_crypt.h"

int main(void)
{
	char *strPwd = "dljfoaq8y23rfwiy23roaq8y23rfrvwiy23roaq8y23rfrvAOUGwifrvAOUGoaAOUGwifrvAOUGoarvAOUGwi";
	char *str = "oaoaq8oaq8y23rfrvoaq8y23rfrvAOUGwiAOUGwiy23roaq8y23rfrvAOUGwifrvAOUGoaq8y23rfrvAOUGwiwioaq8y23rfroaq8y23rfrvAOUGwivAOUGwoaq8y23rfrvAOUGwiiq8oaq8y23rfrvAOoaq8y23rfrvAOUGwiUGwiy23rfrvoaq8yoaq8y23rfrvAOUGwi23rfrvAOUGwoaq8y23rfrvAOoaq8y23roaq8y23rfrvAOUGwifrvAOUGwiUGwiiAOoaq8y23rfrvAOoaq8y23rfrvAOUGwiUGwioaq8y23rfrvAOUGwioaq8y23rfrvAOUGwiUGoaq8y23rfrvAOUGoaq8oaq8y23rfrvAOUGwiy23rfrvoaq8y23rfrvAOUGwiAOUGwoaq8y23rfrvAOUGwiiwiwi";
	char *str2 = "<-+++++->oaoaq8oaq8y23rfrvoaq8y23rfrvAOUGwiAOUGwiy23roaq8y23rfrvAOUGwifrvAOUGoaq8y23rfrvAOUGwiwioaq8y23rfroaq8y23rfrvAOUGwivAOUGwoaq8y23rfrvAOUGwiiq8oaq8y23rfrvAOoaq8y23rfrvAOUGwiUGwiy23rfrvoaq8yoaq8y23rfrvAOUGwi23rfrvAOUGwoaq8y23rfrvAOoaq8y23roaq8y23rfrvAOUGwifrvAOUGwiUGwiiAOoaq8y23rfrvAOoaq8y23rfrvAOUGwiUGwioaq8y23rfrvAOUGwioaq8y23rfrvAOUGwiUGoaq8y23rfrvAOUGoaq8oaq8y23rfrvAOUGwiy23rfrvoaq8y23rfrvAOUGwiAOUGwoaq8y23rfrvAOUGwiiwiwi";
	int str_len = strlen(str);
	int str2_len = strlen(str2);
	unsigned char *crypt_iv = (unsigned char *)malloc(16);
	if(randomIV(crypt_iv) != 16)
	{
		return 0;
	}
	/*
	if(randomIv(crypt_iv) != 16)
	{
		return 0;
	}
	*/
	unsigned char *out = (unsigned char *)malloc((str_len + str2_len + 16 + 1) * sizeof(char));
	aes_256_cfb_crypt((const unsigned char *)str, out, str_len, strPwd, crypt_iv, ENC_IV_ENCRYPT);
	//out length = encrypted iv(16 Bytes) + encrypted str(str_len Bytes)
	aes_256_cfb_crypt((const unsigned char *)str2, out + str_len + 16, str2_len, strPwd, crypt_iv, REUSE_IV_ENCRYPT);
	//out length = encrypted iv(16 Bytes) + encrypted str(str_len Bytes) + encrypted str2(str2_len Bytes)
	out[16 + str_len + str2_len] = '\0';
	//printf("%s\n", out);

	unsigned char *out2 = (unsigned char *)malloc((str_len + str2_len + 1) * sizeof(char));
	aes_256_cfb_crypt((const unsigned char *)out, out2, str_len + 16, strPwd, crypt_iv, ENC_IV_DECRYPT);
	//out2 length = str_len Bytes
	aes_256_cfb_crypt((const unsigned char *)(out + str_len + 16), out2 + str_len, str2_len, strPwd, crypt_iv, REUSE_IV_DECRYPT);
	//out2 length = str_len Bytes + str2_len Bytes
	out2[str_len + str2_len] = '\0';
	printf("\ndecrypted -> %s\n", out2);
	free(crypt_iv);
	free(out);
	free(out2);
}