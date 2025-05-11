#include <stdio.h>  
#include <string.h>  
#include <stdint.h>  
#include <stdlib.h>  
#include "gmssl/rand.h"  
#include "gmssl/sm4.h"  

// 宏定义明文长度（至少130字节）  
#define PLAINTEXT_LEN 130  

// 打印十六进制数据  
void print_hex(const char *title, const uint8_t *data, size_t len) {  
    printf("%s:", title);  
    for (size_t i = 0; i < len; i++) {  
        if (i % 16 == 0) {  
            printf("\n%04zx: ", i);  
        }  
        printf("%02X ", data[i]);  
    }  
    printf("\n");  
}  

int main() {  
    int ret = 0;  
    uint8_t key[SM4_KEY_SIZE];  
    uint8_t iv[SM4_BLOCK_SIZE];  
    uint8_t plaintext[PLAINTEXT_LEN];  
    uint8_t ciphertext[PLAINTEXT_LEN + SM4_BLOCK_SIZE]; // 预留填充空间  
    uint8_t decrypted[PLAINTEXT_LEN + SM4_BLOCK_SIZE];  
    size_t outlen = 0;  
    size_t total_outlen = 0;  

    // 生成随机 Key  
    if (rand_bytes(key, sizeof(key)) != 1) {  
        fprintf(stderr, "生成随机 Key 失败\n");  
        return 1;  
    }  

    // 生成随机 IV  
    if (rand_bytes(iv, sizeof(iv)) != 1) {  
        fprintf(stderr, "生成随机 IV 失败\n");  
        return 1;  
    }  

    // 定义明文（至少130字节）  
    memset(plaintext, 'A', sizeof(plaintext)); // 用字符 'A' 填充  
    // 可选：添加一些变化  
    plaintext[0] = 'H';  
    plaintext[1] = 'e';  
    plaintext[2] = 'l';  
    plaintext[3] = 'l';  
    plaintext[4] = 'o';  
    plaintext[5] = ',';  
    plaintext[6] = ' ';  
    plaintext[7] = 'S';  
    plaintext[8] = 'M';  
    plaintext[9] = '4';  
    plaintext[10] = '!';  
    // 其余部分保持 'A'  

    printf("原文（ASCII）:\n%.*s\n\n", (int)PLAINTEXT_LEN, plaintext);  
    print_hex("原文（十六进制）", plaintext, PLAINTEXT_LEN);  

    // 初始化加密上下文  
    SM4_CBC_CTX encrypt_ctx;  
    ret = sm4_cbc_encrypt_init(&encrypt_ctx, key, iv);  
    if (ret != 1) {  
        fprintf(stderr, "sm4_cbc_encrypt_init 失败\n");  
        return 1;  
    }  

    // 加密过程  
    ret = sm4_cbc_encrypt_update(&encrypt_ctx, plaintext, PLAINTEXT_LEN, ciphertext, &outlen);  
    if (ret != 1) {  
        fprintf(stderr, "sm4_cbc_encrypt_update 失败\n");  
        return 1;  
    }  
    total_outlen += outlen;  

    ret = sm4_cbc_encrypt_finish(&encrypt_ctx, ciphertext + total_outlen, &outlen);  
    if (ret != 1) {  
        fprintf(stderr, "sm4_cbc_encrypt_finish 失败\n");  
        return 1;  
    }  
    total_outlen += outlen;  

    printf("\n密文（十六进制）：");  
    print_hex("密文", ciphertext, total_outlen);  

    // 初始化解密上下文  
    SM4_CBC_CTX decrypt_ctx;  
    ret = sm4_cbc_decrypt_init(&decrypt_ctx, key, iv);  
    if (ret != 1) {  
        fprintf(stderr, "sm4_cbc_decrypt_init 失败\n");  
        return 1;  
    }  

    // 解密过程  
    size_t decrypted_len = 0;  
    ret = sm4_cbc_decrypt_update(&decrypt_ctx, ciphertext, total_outlen, decrypted, &outlen);  
    if (ret != 1) {  
        fprintf(stderr, "sm4_cbc_decrypt_update 失败\n");  
        return 1;  
    }  
    decrypted_len += outlen;  

    ret = sm4_cbc_decrypt_finish(&decrypt_ctx, decrypted + decrypted_len, &outlen);  
    if (ret != 1) {  
        fprintf(stderr, "sm4_cbc_decrypt_finish 失败\n");  
        return 1;  
    }  
    decrypted_len += outlen;  

    printf("\n解密后的明文（ASCII）:\n%.*s\n\n", (int)decrypted_len, decrypted);  
    print_hex("解密后的明文（十六进制）", decrypted, decrypted_len);  

    // 验证解密结果是否与原文一致  
    if (decrypted_len != PLAINTEXT_LEN || memcmp(plaintext, decrypted, PLAINTEXT_LEN) != 0) {  
        fprintf(stderr, "解密后的明文与原文不一致！\n");  
        return 1;  
    }  

    printf("\n解密成功，明文与原文一致。\n");  

    return 0;  
}
