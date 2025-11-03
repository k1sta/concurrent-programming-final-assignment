#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>
#include <stdint.h>

#define MAX_PASSWORD_LEN 10
#define CHARSET_SIZE 62
#define BLOCK_SIZE 256
#define BLOCKS_PER_GRID 1024

__constant__ char d_charset[CHARSET_SIZE];
__constant__ uint32_t d_target_hash[4];

// MD5 constants
__constant__ uint32_t d_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

__constant__ int d_r[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

__device__ uint32_t leftrotate(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

/*
__device__ void md5_hash(const char* msg, int len, uint32_t* result) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;

    uint8_t buffer[64];
    memset(buffer, 0, 64);
    memcpy(buffer, msg, len);
    buffer[len] = 0x80;
    
    uint32_t bits = len * 8;
    memcpy(buffer + 56, &bits, 4);

    uint32_t* w = (uint32_t*)buffer;

    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) {
            f = (h1 & h2) | ((~h1) & h3);
            g = i;
        } else if (i < 32) {
            f = (h3 & h1) | ((~h3) & h2);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = h1 ^ h2 ^ h3;
            g = (3 * i + 5) % 16;
        } else {
            f = h2 ^ (h1 | (~h3));
            g = (7 * i) % 16;
        }

        uint32_t temp = h0 + f + d_k[i] + w[g];
        temp = leftrotate(temp, d_r[i]);
        h0 = h3;
        h3 = h2;
        h2 = h1;
        h1 = h1 + temp;
    }

    result[0] = h0 + 0x67452301;
    result[1] = h1 + 0xefcdab89;
    result[2] = h2 + 0x98badcfe;
    result[3] = h3 + 0x10325476;
}
*/

__device__ void md5_hash(const char* msg, int len, uint32_t* result) {
    uint32_t a = 0x67452301;
    uint32_t b = 0xefcdab89;
    uint32_t c = 0x98badcfe;
    uint32_t d = 0x10325476;

    uint8_t buffer[64];
    memset(buffer, 0, 64);
    memcpy(buffer, msg, len);
    buffer[len] = 0x80;
    
    uint32_t bits = len * 8;
    memcpy(buffer + 56, &bits, 4);

    uint32_t* w = (uint32_t*)buffer;

    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + leftrotate(a + f + d_k[i] + w[g], d_r[i]);
        a = temp;
    }

    result[0] = a + 0x67452301;
    result[1] = b + 0xefcdab89;
    result[2] = c + 0x98badcfe;
    result[3] = d + 0x10325476;
}

__device__ void generate_password(unsigned long long idx, int len, char* pwd) {
    for (int i = len - 1; i >= 0; i--) {
        pwd[i] = d_charset[idx % CHARSET_SIZE];
        idx /= CHARSET_SIZE;
    }
}

__global__ void crack_kernel(unsigned long long start_idx, int length, unsigned long long total_keyspace, int* found, char* result) {
    unsigned long long idx = start_idx + blockIdx.x * blockDim.x + threadIdx.x;
   
    if (idx >= total_keyspace){
      return;
    }

    if (*found) return;

    char pwd[MAX_PASSWORD_LEN + 1];
    pwd[length] = '\0';
    
    generate_password(idx, length, pwd);
    
    uint32_t hash[4];
    md5_hash(pwd, length, hash);
    if (hash[0] == d_target_hash[0] && hash[1] == d_target_hash[1] && 
        hash[2] == d_target_hash[2] && hash[3] == d_target_hash[3]) {
        int old = atomicCAS(found, 0, 1);
        if (old == 0) {
            for (int i = 0; i <= length; i++) {
                result[i] = pwd[i];
            }
        }
    }
}

unsigned long long pow_ull(int base, int exp) {
    unsigned long long result = 1;
    for (int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

void hex_to_uint32(const char* hex, uint32_t* out) {

	uint8_t bytes[16];
	for (int i = 0; i < 16; i++) {
		unsigned int byte_val;
		sscanf(hex + i * 2, "%2x", &byte_val);
		bytes[i] = (uint8_t)byte_val;
	}
	// Convert bytes to uint32_t in little-endian order 
	for (int i = 0; i < 4; i++) {
		out[i] = bytes[i*4] | (bytes[i*4+1] << 8) | (bytes[i*4+2] << 16) | (bytes[i*4+3] << 24);
	}
}

int main() {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "0123456789";
                           //"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    
    const int length_order[] = {8, 7, 9, 10, 6, 5, 4, 3, 2, 1};

    char target_hash[33];
    printf("Enter MD5 hash: ");
    scanf("%32s", target_hash);
    target_hash[32] = '\0';

    for (int i = 0; i < 32; i++) {
        if (target_hash[i] >= 'A' && target_hash[i] <= 'F') {
            target_hash[i] = target_hash[i] - 'A' + 'a';
        }
    }

    uint32_t h_target_hash[4];
    hex_to_uint32(target_hash, h_target_hash);

    //cudaMemcpyToSymbol(d_charset, charset, CHARSET_SIZE);
    //cudaMemcpyToSymbol(d_target_hash, h_target_hash, 4 * sizeof(uint32_t));

  // ADD ERROR CHECKING HERE
  cudaError_t err = cudaMemcpyToSymbol(d_charset, charset, CHARSET_SIZE);
  if (err != cudaSuccess) {
      printf("Error copying charset: %s\n", cudaGetErrorString(err));
      return 1;
  }

  err = cudaMemcpyToSymbol(d_target_hash, h_target_hash, 4 * sizeof(uint32_t));
  if (err != cudaSuccess) {
    printf("Error copying target hash: %s\n", cudaGetErrorString(err));
    return 1;
  }

    int* d_found;
    char* d_result;
    int h_found = 0;
    char h_result[MAX_PASSWORD_LEN + 1] = {0};

    cudaMalloc(&d_found, sizeof(int));
    cudaMalloc(&d_result, MAX_PASSWORD_LEN + 1);
    cudaMemcpy(d_found, &h_found, sizeof(int), cudaMemcpyHostToDevice);

    cudaEvent_t start_event, stop_event;
    float milliseconds = 0;

    cudaEventCreate(&start_event);
    cudaEventCreate(&stop_event);

    printf("Starting CUDA brute force attack...\n");

    cudaEventRecord(start_event, 0);

    for (int l = 0; l < 10 && !h_found; l++) {
        int length = length_order[l];
        
	printf("Testing passwords of length %d...\n", length);
	//initializing total before loop
	unsigned long long total = pow_ull(CHARSET_SIZE, length);
	
        for (unsigned long long start = 0; start < total && !h_found; start += BLOCK_SIZE * BLOCKS_PER_GRID) {
	    //passing it to the kernel
            crack_kernel<<<BLOCKS_PER_GRID, BLOCK_SIZE>>>(start, length, total, d_found, d_result);
            cudaDeviceSynchronize();
            
            cudaMemcpy(&h_found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
            
            if (start % 10000000 == 0) {
                printf("Progress: %.2f%%\r", (100.0 * start) / total);
                fflush(stdout);
            }
        }
        
        if (h_found) {
            cudaMemcpy(h_result, d_result, MAX_PASSWORD_LEN + 1, cudaMemcpyDeviceToHost);
            break;
        }
        printf("Progress: 100.00%%\n");
    }

    cudaEventRecord(stop_event, 0);
    cudaEventSynchronize(stop_event); // Espera a GPU terminar
    cudaEventElapsedTime(&milliseconds, start_event, stop_event);

    if (h_found) {
        printf("\nPassword found: %s\n", h_result);
    } else {
        printf("\nPassword not found.\n");
    }

    printf("Tempo total de execucao na GPU: %.2f ms (ou %.3f segundos)\n", 
           milliseconds, milliseconds / 1000.0);

    cudaFree(d_found);
    cudaFree(d_result);

    return h_found ? 0 : 1;
}
