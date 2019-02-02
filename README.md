# aes_cfb_crypt

unsigned char *key = (unsigned char *)malloc(32);

unsigned char *iv = (unsigned char *)malloc(16);

//set key and iv :

sha384_key_iv(user_password, strlen(user_password), key, iv);


random_iv = (unsigned char *)malloc(16);

//set random_iv :

randomIV(random_iv);


//encrypt

AES_KEY aesKey;

int setKey = AES_set_encrypt_key((const unsigned char *)key, 256, &aesKey);

AES_cfb128_encrypt(random_iv, encrypted_text, 16, (const void *)&aesKey, iv, &num, AES_ENCRYPT);

AES_cfb128_encrypt(plain_text, encrypted_text + 16, strlen(plain_text), (const void *)&aesKey, random_iv, &num, AES_ENCRYPT);


//decrypt

AES_KEY aesKey;

int setKey = AES_set_encrypt_key((const unsigned char *)key, 256, &aesKey);

AES_cfb128_encrypt(encrypted_text, random_iv, 16, (const void *)&aesKey, iv, &num, AES_DECRYPT);

AES_cfb128_encrypt(encrypted_text + 16, plain_text, strlen(encrypted_text) - 16, (const void *)&aesKey, random_iv, &num, AES_DECRYPT);


# --------------------------------------------------------------
# build : 

windows with mingw :

gcc *.c -O3 -o cryptFile.exe -static -Wall


linux :

gcc *.c -O3 -o cryptFile -static -Wall


android with NDK :

gcc *.c -O3 -o cryptFile -static -Wall

OR call it with jni


# --------------------------------------------------------------
# License : 

follow OpenSSL 1.1.1
