#include <stdio.h>
#include <stdlib.h>
#include "gmssl/rand.h" // 注意 GmSSL 可能的头文件路径

int main() {
    unsigned char random_bytes[20];
    
    // 使用 GmSSL 的 RAND_bytes 函数生成随机数
    if (rand_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        fprintf(stderr, "Error generating random bytes.\n");
        return 1;
    }

    printf("Random bytes: ");
    for (int i = 0; i < sizeof(random_bytes); i++) {
        // 以十六进制格式打印随机字节
        printf("%02x", random_bytes[i]);
    }
    printf("\n");

    return 0;
}
