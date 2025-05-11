/*  
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.  
 *  
 *  Licensed under the Apache License, Version 2.0 (the License); you may  
 *  not use this file except in compliance with the License.  
 *  
 *  http://www.apache.org/licenses/LICENSE-2.0  
 */  

#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <stdint.h>  
#include "gmssl/sm4.h"
#include "gmssl/rand.h"

// 定义明文最小长度  
#define PLAINTEXT_MIN_SIZE 130  

int main() {  
    // 生成随机密钥  
    uint8_t key[SM4_KEY_SIZE];  
    if (rand_bytes(key, SM4_KEY_SIZE) != 1) {  
        fprintf(stderr, "随机密钥生成失败。\n");  
        return EXIT_FAILURE;  
    }  

    // 生成随机IV  
    uint8_t iv[SM4_BLOCK_SIZE];  
    if (rand_bytes(iv, SM4_BLOCK_SIZE) != 1) {  
        fprintf(stderr, "随机IV生成失败。\n");  
        return EXIT_FAILURE;  
    }  

    // 打印生成的密钥  
    printf("随机生成的密钥: ");  
    for (size_t i = 0; i < SM4_KEY_SIZE; i++) {  
        printf("%02X ", key[i]);  
    }  
    printf("\n");  

    // 打印生成的IV  
    printf("随机生成的IV: ");  
    for (size_t i = 0; i < SM4_BLOCK_SIZE; i++) {  
        printf("%02X ", iv[i]);  
    }  
    printf("\n");  

    // 定义明文（不少于130字节）  
    uint8_t plaintext[PLAINTEXT_MIN_SIZE];  
    if (rand_bytes(plaintext, PLAINTEXT_MIN_SIZE) != 1) {  
        fprintf(stderr, "随机明文生成失败。\n");  
        return EXIT_FAILURE;  
    }  

    // 打印明文（以十六进制格式）  
    printf("明文 (%d 字节): ", PLAINTEXT_MIN_SIZE);  
    for (size_t i = 0; i < PLAINTEXT_MIN_SIZE; i++) {  
        printf("%02X ", plaintext[i]);  
    }  
    printf("\n");  

    // 初始化 SM4 密钥结构  
    SM4_KEY enc_key, dec_key;  
    sm4_set_encrypt_key(&enc_key, key);  
    sm4_set_decrypt_key(&dec_key, key);  

    // 计算加密后可能的最大长度（明文长度 + 一个块的填充）  
    size_t plaintext_len = PLAINTEXT_MIN_SIZE;  
    size_t max_ciphertext_len = plaintext_len + SM4_BLOCK_SIZE;  
    uint8_t *ciphertext = malloc(max_ciphertext_len);  
    if (ciphertext == NULL) {  
        fprintf(stderr, "内存分配失败。\n");  
        return EXIT_FAILURE;  
    }  

    // 由于加密和解密后的明文长度可能不同，预留足够的空间  
    uint8_t *decryptedtext = malloc(max_ciphertext_len + 1); // +1用于终止符  
    if (decryptedtext == NULL) {  
        fprintf(stderr, "内存分配失败。\n");  
        free(ciphertext);  
        return EXIT_FAILURE;  
    }  

    size_t outlen;  
    int ret;  

    // 加密带填充的明文  
    ret = sm4_cbc_padding_encrypt(&enc_key, iv, plaintext, plaintext_len, ciphertext, &outlen);  
    if (ret != 1) {  
        fprintf(stderr, "加密失败。\n");  
        free(ciphertext);  
        free(decryptedtext);  
        return EXIT_FAILURE;  
    }  

    // 输出密文（十六进制格式）  
    printf("密文 (%zu 字节): ", outlen);  
    for (size_t i = 0; i < outlen; i++) {  
        printf("%02X ", ciphertext[i]);  
    }  
    printf("\n");  

    // 解密带填充的密文  
    ret = sm4_cbc_padding_decrypt(&dec_key, iv, ciphertext, outlen, decryptedtext, &outlen);  
    if (ret != 1) {  
        fprintf(stderr, "解密失败。\n");  
        free(ciphertext);  
        free(decryptedtext);  
        return EXIT_FAILURE;  
    }  

    // 确保解密后的文本是以空字符结尾的字符串  
    decryptedtext[outlen] = '\0';  

    // 打印解密后的明文（以十六进制格式）  
    printf("解密后的明文 (%zu 字节): ", outlen);  
    for (size_t i = 0; i < outlen; i++) {  
        printf("%02X ", decryptedtext[i]);  
    }  
    printf("\n");  

    // 验证解密后的明文是否与原始明文相同  
    if (memcmp(plaintext, decryptedtext, plaintext_len) == 0) {  
        printf("解密验证成功：解密后的明文与原始明文一致。\n");  
    } else {  
        printf("解密验证失败：解密后的明文与原始明文不一致。\n");  
    }  

    // 释放分配的内存  
    free(ciphertext);  
    free(decryptedtext);  

    return EXIT_SUCCESS;  
}
