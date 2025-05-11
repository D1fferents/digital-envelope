#include <stdio.h>  
#include <string.h>  
#include <stdlib.h>  
#include <gmssl/sm2.h>  
#include <gmssl/sm3.h>  
#include <gmssl/error.h>  

// 辅助函数：以十六进制格式打印字节数组  
void print_hex(const char *label, const uint8_t *data, size_t len) {  
    printf("%s: ", label);  
    for(size_t i = 0; i < len; i++) {  
        printf("%02X", data[i]);  
    }  
    printf("\n");  
}  

int main() {  
    int ret = 0;  

    // 1. 生成 SM2 密钥对  
    SM2_KEY key;  
    
    printf("生成 SM2 密钥对...\n");  
    ret = sm2_key_generate(&key);  
    if (ret != 1) {  
        fprintf(stderr, "SM2 密钥生成失败\n");  
        return EXIT_FAILURE;  
    }  
    printf("SM2 密钥生成成功。\n");  

    // 打印生成的公钥和私钥（可选）  
    /*  
    sm2_key_print(stdout, 0, 4, "SM2 公钥", &key);  
    sm2_key_print(stdout, 0, 4, "SM2 私钥", &key);  
    */  

    // 2. 定义要加密的明文  
    const char *plaintext = "Hello, SM2!";  
    size_t plaintext_len = strlen(plaintext);  
    printf("明文: %s\n", plaintext);  

    // 3. 加密明文  
    uint8_t ciphertext[SM2_MAX_CIPHERTEXT_SIZE];  
    size_t ciphertext_len = sizeof(ciphertext);  

    printf("加密明文...\n");  
    ret = sm2_encrypt(&key, (const uint8_t *)plaintext, plaintext_len, ciphertext, &ciphertext_len);  
    if (ret != 1) {  
        fprintf(stderr, "SM2 加密失败\n");  
        return EXIT_FAILURE;  
    }  
    printf("加密成功。\n");  

    // 打印密文  
    print_hex("密文", ciphertext, ciphertext_len);  

    // 4. 解密密文  
    uint8_t decrypted[SM2_MAX_PLAINTEXT_SIZE];  
    size_t decrypted_len = sizeof(decrypted);  

    printf("解密密文...\n");  
    ret = sm2_decrypt(&key, ciphertext, ciphertext_len, decrypted, &decrypted_len);  
    if (ret != 1) {  
        fprintf(stderr, "SM2 解密失败\n");  
        return EXIT_FAILURE;  
    }  
    printf("解密成功。\n");  

    // 确认解密后的明文与原始明文一致  
    decrypted[decrypted_len] = '\0'; // 添加字符串终止符  
    printf("解密后的明文: %s\n", decrypted);  

    // 5. 签名  
    const char *message = "This is a message to be signed.";  
    size_t message_len = strlen(message);  
    printf("要签名的消息: %s\n", message);  

    // 初始化签名上下文  
    SM2_SIGN_CTX sign_ctx;  
    sm2_sign_init(&sign_ctx, &key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);  

    // 更新签名上下文  
    ret = sm2_sign_update(&sign_ctx, (const uint8_t *)message, message_len);  
    if (ret != 1) {  
        fprintf(stderr, "SM2 签名更新失败\n");  
        return EXIT_FAILURE;  
    }  

    // 完成签名  
    uint8_t signature[SM2_MAX_SIGNATURE_SIZE];  
    size_t signature_len = sizeof(signature);  
    ret = sm2_sign_finish(&sign_ctx, signature, &signature_len);  
    if (ret != 1) {  
        fprintf(stderr, "SM2 签名失败\n");  
        return EXIT_FAILURE;  
    }  
    printf("签名成功。\n");  

    // 打印签名  
    print_hex("签名", signature, signature_len);  

    // 6. 验证签名  
    SM2_SIGN_CTX verify_ctx;  
    sm2_verify_init(&verify_ctx, &key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);  

    ret = sm2_verify_update(&verify_ctx, (const uint8_t *)message, message_len);  
    if (ret != 1) {  
        fprintf(stderr, "SM2 签名验证更新失败\n");  
        return EXIT_FAILURE;  
    }  

    ret = sm2_verify_finish(&verify_ctx, signature, signature_len);  
    if (ret == 1) {  
        printf("签名验证成功。\n");  
    } else {  
        printf("签名验证失败。\n");  
        return EXIT_FAILURE;  
    }  

    return EXIT_SUCCESS;  
}
