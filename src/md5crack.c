#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <time.h>
#include <stdbool.h>

#define MAX_PASSWORD_LEN 8
#define NUM_THREADS 16
#define CHARSET_SIZE 26

// debug flag for detailed output (testing)
const bool debug = false;

// flag for found
bool found = false;

// charset: lowercase, uppercase, digits, and (some) special characters
const char charset[] = "abcdefghijklmnopqrstuvwxyz";
                       //"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       //"0123456789";
                       //"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

// password length frequency order (based on analysis)
//const int length_order[] = {8, 7, 9, 10, 6, 5, 4, 3, 2, 1}; // ajustar baseado na bibliografia
const int length_order[] = {8, 7,6, 5, 4, 3, 2, 1};

// thread data struct containing hash 
typedef struct {
    char target_hash[33];   // 33 bytes (32 for the hash and 1 for the trailing char)
    int thread_id;          // thread id
    int num_threads;        // number of threads 
    char *result;
    pthread_mutex_t *mutex;
} thread_data_t;

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

// thread function for brute force search (this is the thing)
void *brute_force_thread(void *arg) {
  thread_data_t *data = (thread_data_t *)arg;
  char pwd_candidate[MAX_PASSWORD_LEN + 1];
  char hash_hex_output[33];                  // string output 
  unsigned char digest_raw[EVP_MAX_MD_SIZE]; // raw byte output
  unsigned int digest_len;                   // raw byte length

  // initiating context for md5 hashing
  EVP_MD_CTX *ctx = EVP_MD_CTX_new(); 
  EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

  // loop through all lengths assigned (e.g., length_order)
  for (int l = 0; l < MAX_PASSWORD_LEN && !found; l++) {
    int length = length_order[l]; // get the length to test
    
    pwd_candidate[length] = '\0'; // set only one time the trailing char

    // this logic is now inside the length loop
    unsigned long long total = total_combinations(length);
    unsigned long long start = (total * data->thread_id) / data->num_threads;
    unsigned long long end = (total * (data->thread_id + 1)) / data->num_threads;

    // progress indicator for thread 0 (the first one? idk man this needs review)
    if (data->thread_id == 0) {
      printf("Testing passwords of length %d...\n", length);
    }

     // password-checking loop based on the assigned length
    for (unsigned long long i = start; i < end && !found; i++) {
      generate_pwd_candidate(i, length, pwd_candidate); // generate_pwd_candidate

      // initialize the context for a new hash (null reutilizes the EVP_md5() callled before :D)
      EVP_DigestInit_ex(ctx, NULL, NULL); 

      // hash the candidate
      EVP_DigestUpdate(ctx, pwd_candidate, length); 

      // finalize the hash
      EVP_DigestFinal_ex(ctx, digest_raw, &digest_len);
            
      // raw digest -> hex string
      bytes_to_hex(digest_raw, hash_hex_output, digest_len);


      if (strcmp(hash_hex_output, data->target_hash) == 0) {
        pthread_mutex_lock(data->mutex);
        if (!found) {
          found = true;
          strcpy(data->result, pwd_candidate);
          // using \n to avoid mixing with progress indicator
          printf("\nThread %d found password: %s\n", data->thread_id, pwd_candidate);
        }
        pthread_mutex_unlock(data->mutex);
        break; // exit inner (i) loop
      }
    }

    // each thread reports its own completion for this length
    pthread_mutex_lock(data->mutex);
    if (!found) {
      // Using \n to create a new line. The padding spaces clear the progress bar.
      printf("Thread %d finished length %d.                         \n", data->thread_id, length);
      fflush(stdout);
    }
    pthread_mutex_unlock(data->mutex);
  }

  EVP_MD_CTX_free(ctx);    
  return NULL;
}

// main cracking function with frequency analysis
bool crack_password_concurrent(const char *target_hash, char *result) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    printf("Starting concurrent brute force attack...\n");
    printf("Target hash: %s\n", target_hash);
    printf("Using %d threads\n\n", NUM_THREADS);

    // creating threads
    for (int i = 0; i < NUM_THREADS; i++) {
        strcpy(thread_data[i].target_hash, target_hash);
        thread_data[i].thread_id = i;
        thread_data[i].num_threads = NUM_THREADS;
        thread_data[i].result = result;
        thread_data[i].mutex = &mutex;

        pthread_create(&threads[i], NULL, brute_force_thread, &thread_data[i]);
    }
        
    // wait for all threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    if (found) {
        printf("\nPassword found!\n");
    } else {
        printf("\nPassword not found.\n");
    }

    pthread_mutex_destroy(&mutex);
    return found;
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

  printf("Starting sequential brute force attack...\n");
  printf("Target hash: %s\n\n", target_hash);

  // loops for every lengthfor (int l = 0; l < 10; l++) {
  for(int l = 0; l < MAX_PASSWORD_LEN; l++){
    int length = length_order[l]; // grabs length from frequency analysis
    printf("Testing passwords of length %d...\n", length);  
      
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
        printf("Password found: %s\n\n", pwd_candidate);
        return true;
      }
      
      // dipslay the progress for the user
      if (i % 1000000 == 0) {
        printf("Progress: %.2f%%\r", (100.0 * i) / total);
        fflush(stdout);
        }
    }
    
    // bad ending :(
    printf("Length %d exhausted.\n\n", length);
  }

  return false;
}

int main(int argc, char *argv[]) {
  if (argc < 2 || argc > 3) {
    printf("Usage: %s <md5_hash> [mode]\n", argv[0]);
    printf("Modes: -s (sequential), -c (concurrent) [default: concurrent]\n");
    printf("\nSome test cases:\n");
    printf("  cce36d2833156c007b1c6c644828ad37  -> c0r1nTh14n\n");
    printf("  4aef3d4d3dd9e36d3042309458b04314  -> senhaL3gal\n");
    printf("  d6fe902a1d89be1731428be31caf9586  -> xXs3nh4Xx\n");
    printf("  f8772716367e5a3b5145fff616c27ba1  -> 0028122004\n");
    printf("  b21f91d078060d5f655f5e8b5381f8a3  -> mostarda\n");
    return 1;
  }

  // detecting if its concurrent or sequential access
  bool sequential = false;
  
  if (argc == 3) {
    if(strcmp(argv[2], "-s") == 0) sequential = true;
    else if(strcmp(argv[2], "-c") != 0){
      printf("Usage: %s <md5_hash> [mode]\n", argv[0]);
      printf("Modes: -s (sequential), -c (concurrent) [default: concurrent]\n");
      printf("\nSome test cases:\n");
      printf("  cce36d2833156c007b1c6c644828ad37  -> c0r1nTh14n\n");
      printf("  4aef3d4d3dd9e36d3042309458b04314  -> senhaL3gal\n");
      printf("  d6fe902a1d89be1731428be31caf9586  -> xXs3nh4Xx\n");
      printf("  f8772716367e5a3b5145fff616c27ba1  -> 0028122004\n");
      printf("  b21f91d078060d5f655f5e8b5381f8a3  -> mostarda\n");
      return 1;
    }
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

  // time measurement
  char result[MAX_PASSWORD_LEN + 1] = {0};
  
  struct timespec start_time, end_time;
  clock_gettime(CLOCK_MONOTONIC, &start_time);

  // THE thing.
  bool success;
  if (sequential) {
    success = crack_password_sequential(target_hash, result);
  } else {
    success = crack_password_concurrent(target_hash, result);
  }

  // ending time measurement
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  double time_spent = (end_time.tv_sec - start_time.tv_sec);
  time_spent += (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

  if (success) {
    printf("SUCCESS!\n");
    printf("Password: %s\n", result);
    printf("Time taken: %.2f seconds\n", time_spent);
  } else {
    printf("FAILED!\n");
    printf("Password not found within search space.\n");
    printf("Time taken: %.2f seconds\n", time_spent);
  }

  return success ? 0 : 1;
}
