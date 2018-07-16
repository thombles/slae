#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

void print_hex(unsigned char *buffer, unsigned int length) {
  for (int i = 0; i < length; i++) {
    printf("\\x%02x", buffer[i]);
  }
}

int main(int argc, char *argv[]) {
  if (sodium_init() < 0) {
    fprintf(stderr, "Cannot initialise libsodium!\n");
    exit(1);
  }

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <password>\n", argv[0]);
    fprintf(stderr, "Plaintext shellcode is read from stdin\n");
    fprintf(stderr, "encrypted.h is written to stdout\n");
    fprintf(stderr, "Plaintext should not contain nulls\n");
    exit(1);
  }

  char *password = argv[1];

  /* Create a random salt for the key derivation function */
  unsigned char salt[crypto_pwhash_SALTBYTES];
  randombytes_buf(salt, sizeof salt);

  /* Use argon2 to convert password to a full size key */
  unsigned char key[crypto_secretbox_KEYBYTES];
  if (crypto_pwhash(key, sizeof key, password, strlen(password), salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    fprintf(stderr, "Key derivation failed\n");
    exit(1);
  }

  /* Create a random nonce for the encryption also */
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof nonce);
  
  /* Read in the shellcode to be crypted */
  char plaintext[4096];
  if (!fgets(plaintext, sizeof plaintext, stdin)) {
    fprintf(stderr, "Problem reading shellcode from stdin");
    exit(1);
  }

  /* Now encrypt it into ciphertext */
  unsigned long ciphertext_len = crypto_secretbox_MACBYTES + strlen(plaintext);
  unsigned char *ciphertext = alloca(ciphertext_len);
  crypto_secretbox_easy(ciphertext, (unsigned char *)plaintext, strlen(plaintext), nonce, key);

  /* Output the contents of encrypted.h */
  printf("/* encrypted.h */\n");
  
  printf("unsigned char nonce[] = \"");
  print_hex(nonce, sizeof nonce);
  printf("\";\n");
  
  printf("unsigned char salt[] = \"");
  print_hex(salt, sizeof salt);
  printf("\";\n");
  
  printf("unsigned char ciphertext[] = \"");
  print_hex(ciphertext, ciphertext_len);
  printf("\";\n");

  printf("unsigned int ciphertext_len = %ld;\n", ciphertext_len);
}
