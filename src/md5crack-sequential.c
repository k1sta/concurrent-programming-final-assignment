#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <time.h>
#include <stdbool.h>

#define MAX_PASSWORD_LEN 10
#define CHARSET_SIZE 62

// flag for found
bool found = false;

// charset: lowercase, uppercase, digits, and (some) special characters
const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       "0123456789";
                       //"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

// password length frequency order (based on analysis)
const int length_order[] = {8, 7, 9, 10, 6, 5, 4, 3, 2, 1}; // ajustar baseado na bibliografia


// convert bytes to hex string without libraries bc we love C language <3
void bytes_to_hex(unsigned char *bytes, char *hex, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}


/*
 * generate password at given index for a specific length
 * we're usign base conversion properties that guarantee an iteration for every possible password here
 *
 * imagine a 4-size password that has a CHARSET_SIZE of 26 (alphabet). in this case, we initially will have index 0
 *
 * the function will start creating the password from the last character, so that means the end char will be charset[index%CHARSET_SIZE] == charset[0]
 *
 * well update index with index/CHARSET_SIZE, so it'll stay 0
 *
 * so the password wil be smth like "aaaa"
 *
 * for index == 1, the last char will be charset[1] ("b")
 *
 * so well have "aaab" (the third char will be truncated to 0 because of the integer division)
 *
 * index == 2 => "aaac"
 * index == 3 => "aaad"
 * .
 * .
 * .
 * index == CHARSET_SIZE => "aaba" (because of base conversion)
 *
 * hope it's clear :D
*/
void generate_pwd_candidate(unsigned long long index, int length, char *password) {
  // loop creating the password
  for (int i = length - 1; i >= 0; i--) {
    password[i] = charset[index % CHARSET_SIZE];
    index /= CHARSET_SIZE;
  }
}

// calculate total combinations for a given length for previewing the progress
unsigned long long total_combinations(int length) {
  unsigned long long total = 1; // neutral element

  // CHARSET_SIZE^(lenght)
  for (int i = 0; i < length; i++) {
    total *= CHARSET_SIZE;
  }

  return total;
}

// Sequential version for comparison
bool crack_password_sequential(const char *target_hash, char *result) {
  char pwd_candidate[MAX_PASSWORD_LEN + 1];
  char hash_hex_output[33];                  // string output
  unsigned char digest_raw[EVP_MAX_MD_SIZE]; // raw byte output
  unsigned int digest_len;                   // raw byte length

  // initiating context for md5 hashing
  EVP_MD_CTX *ctx = EVP_MD_CTX_new(); 
  EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

    // loops for every length
  for (int l = 0; l < 10; l++) {
    int length = length_order[l]; // grabs length from frequency analysis
    unsigned long long total = total_combinations(length);
    
    pwd_candidate[length] = '\0';

    for (unsigned long long i = 0; i < total; i++) {
      generate_pwd_candidate(i, length, pwd_candidate); // generate candidate

      // initialize the context for a new hash (null reutilizes the EVP_md5() callled before :D)
      EVP_DigestInit_ex(ctx, NULL, NULL); 

      // hash the candidate
      EVP_DigestUpdate(ctx, pwd_candidate, length); 

      // finalize the hash
      EVP_DigestFinal_ex(ctx, digest_raw, &digest_len);
            
      // raw digest -> hex string
      bytes_to_hex(digest_raw, hash_hex_output, digest_len);


      if (strcmp(hash_hex_output, target_hash) == 0) {        // if the candidate hash matches the target hash, its over! we won!
        strcpy(result, pwd_candidate); 
        return true;
      }
   }
  }

  return false;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Uso: %s <hash_md5>\n", argv[0]);
    fprintf(stderr, "Exemplo: %s 5d41402abc4b2a76b9719d911017c592\n", argv[0]);
    return 1;
  }

  if (strlen(argv[1]) != 32) {
    fprintf(stderr, "Erro: O hash MD5 deve ter 32 caracteres.\n");
    return 1;
  }

  // collecting target hash
  char target_hash[33];
  strncpy(target_hash, argv[1], 32);
  target_hash[32] = '\0';

  // convert to lowercase for comparison
  for (int i = 0; i < 32; i++) {
    // md5 only contains characters between 'a' and 'f'
    if (target_hash[i] >= 'A' && target_hash[i] <= 'F') {
      // positioning into the lowercase based on the index at the uppercase
      target_hash[i] = target_hash[i] - 'A' + 'a';
    }
  }

  //result buffer
  char result[MAX_PASSWORD_LEN + 1] = {0};
  
  // THE thing.
  bool success;
  success = crack_password_sequential(target_hash, result);


    if (success) {
        printf("\nPassword found: %s\n", result);
    } else {
        printf("\nPassword not found.\n");
    }

  return success ? 0 : 1;
}
