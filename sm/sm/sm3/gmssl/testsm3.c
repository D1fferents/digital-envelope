#include <stdio.h>
#include <string.h>
#include <gmssl/sm3.h>

int main() {
    const char *data = "Hello, GmSSL SM3!";
    unsigned char hash[SM3_DIGEST_SIZE];  // SM3_DIGEST_SIZE is the length of the hash

    SM3_CTX ctx;
    sm3_init(&ctx);  // Initialize the hash context
    sm3_update(&ctx, (const unsigned char *)data, strlen(data));  // Hash the data
    sm3_finish(&ctx, hash);  // Finalize the hash

    printf("SM3 hash: ");
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
