# aes_cfb_crypt
build for test : 

gcc *.c -O3 -o testCFB -static -Wall


unsigned char *key = (unsigned char *)malloc(32);
unsigned char *iv = (unsigned char *)malloc(16);
sha384_key_iv(user_password, strlen(user_password), key, iv);
AES_KEY aesKey;
int setKey = AES_set_encrypt_key((const unsigned char *)key, 256, &aesKey);
AES_cfb128_encrypt(random_iv, encrypted_text, 16, (const void *)&aesKey, iv, &num, AES_ENCRYPT);
AES_cfb128_encrypt(plain_text, encrypted_text + 16, strlen(plain_text), (const void *)&aesKey, random_iv, &num, AES_ENCRYPT);

License : 
follow OpenSSL 1.1.1
