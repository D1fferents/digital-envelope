#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>

/* 辅助函数：以十六进制格式打印字节数组 */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void) {
    int ret = 0;

    /***************** 模拟密钥对生成 ******************/
    // 生成发送方的 SM2 密钥对（用于签名）
    SM2_KEY sender_key;
    ret = sm2_key_generate(&sender_key);
    if (ret != 1) {
        fprintf(stderr, "发送方 SM2 密钥生成失败\n");
        return EXIT_FAILURE;
    }
    
    // 生成接收方的 SM2 密钥对（用于加密会话密钥）
    SM2_KEY recipient_key;
    ret = sm2_key_generate(&recipient_key);
    if (ret != 1) {
        fprintf(stderr, "接收方 SM2 密钥生成失败\n");
        return EXIT_FAILURE;
    }
    printf("发送方和接收方 SM2 密钥对生成成功。\n\n");

    /***************** 发送端操作 ******************/
    // 1. 生成 SM4 会话密钥及 IV
    uint8_t session_key[SM4_KEY_SIZE];
    if (rand_bytes(session_key, SM4_KEY_SIZE) != 1) {
        fprintf(stderr, "SM4 会话密钥生成失败。\n");
        return EXIT_FAILURE;
    }
    uint8_t iv[SM4_BLOCK_SIZE];
    if (rand_bytes(iv, SM4_BLOCK_SIZE) != 1) {
        fprintf(stderr, "SM4 IV 生成失败。\n");
        return EXIT_FAILURE;
    }
    print_hex("会话密钥", session_key, SM4_KEY_SIZE);
    print_hex("IV", iv, SM4_BLOCK_SIZE);
    printf("\n");

    // 2. 定义明文数据
    const char *plaintext = "Hello, Digital Envelope! This is a test message.";
    size_t plaintext_len = strlen(plaintext);
    printf("明文: %s\n\n", plaintext);

    // 3. 使用 SM4 对明文进行加密（CBC 模式，带填充）
    SM4_KEY sm4_enc_key;
    sm4_set_encrypt_key(&sm4_enc_key, session_key);
    size_t max_ciphertext_len = plaintext_len + SM4_BLOCK_SIZE;
    uint8_t *ciphertext = malloc(max_ciphertext_len);
    if (ciphertext == NULL) {
        fprintf(stderr, "内存分配失败。\n");
        return EXIT_FAILURE;
    }
    size_t ciphertext_len = max_ciphertext_len;
    ret = sm4_cbc_padding_encrypt(&sm4_enc_key, iv, (const uint8_t *)plaintext, plaintext_len, ciphertext, &ciphertext_len);
    if (ret != 1) {
        fprintf(stderr, "SM4 加密失败。\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }
    print_hex("密文", ciphertext, ciphertext_len);
    printf("\n");

    // 4. 使用接收方的 SM2 公钥加密会话密钥
    uint8_t encrypted_session_key[SM2_MAX_CIPHERTEXT_SIZE];
    size_t encrypted_session_key_len = sizeof(encrypted_session_key);
    ret = sm2_encrypt(&recipient_key, session_key, SM4_KEY_SIZE,
                      encrypted_session_key, &encrypted_session_key_len);
    if (ret != 1) {
        fprintf(stderr, "SM2 加密会话密钥失败。\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }
    print_hex("加密后的会话密钥", encrypted_session_key, encrypted_session_key_len);
    printf("\n");

    // 5. 计算 SM3 摘要并使用发送方的 SM2 私钥对明文签名
    SM3_CTX sm3_ctx;
    uint8_t digest[SM3_DIGEST_SIZE];
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, (const uint8_t *)plaintext, plaintext_len);
    sm3_finish(&sm3_ctx, digest);
    print_hex("SM3 摘要", digest, SM3_DIGEST_SIZE);

    SM2_SIGN_CTX sign_ctx;
    ret = sm2_sign_init(&sign_ctx, &sender_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
    if (ret != 1) {
        fprintf(stderr, "SM2 签名初始化失败。\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }
    ret = sm2_sign_update(&sign_ctx, (const uint8_t *)plaintext, plaintext_len);
    if (ret != 1) {
        fprintf(stderr, "SM2 签名更新失败。\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }
    uint8_t signature[SM2_MAX_SIGNATURE_SIZE];
    size_t signature_len = sizeof(signature);
    ret = sm2_sign_finish(&sign_ctx, signature, &signature_len);
    if (ret != 1) {
        fprintf(stderr, "SM2 签名失败。\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }
    print_hex("签名", signature, signature_len);
    printf("\n");

    /* 模拟数字信封的发送：
       信封包含：加密后的会话密钥、IV、密文和签名 */

    /***************** 接收端操作 ******************/
    // 1. 接收方使用自己的 SM2 私钥解密加密的会话密钥
    uint8_t recovered_session_key[SM4_KEY_SIZE];
    size_t recovered_session_key_len = sizeof(recovered_session_key);
    ret = sm2_decrypt(&recipient_key, encrypted_session_key, encrypted_session_key_len,
                      recovered_session_key, &recovered_session_key_len);
    if (ret != 1) {
        fprintf(stderr, "SM2 解密会话密钥失败。\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }
    print_hex("恢复的会话密钥", recovered_session_key, recovered_session_key_len);
    if (memcmp(session_key, recovered_session_key, SM4_KEY_SIZE) == 0) {
        printf("会话密钥恢复一致。\n\n");
    } else {
        printf("会话密钥恢复不一致！\n\n");
    }

    // 2. 使用恢复的会话密钥和 IV 对密文进行解密
    SM4_KEY sm4_dec_key;
    sm4_set_decrypt_key(&sm4_dec_key, recovered_session_key);
    uint8_t *decryptedtext = malloc(max_ciphertext_len + SM4_BLOCK_SIZE);
    if (decryptedtext == NULL) {
        fprintf(stderr, "内存分配失败。\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }
    size_t decryptedtext_len = max_ciphertext_len;
    ret = sm4_cbc_padding_decrypt(&sm4_dec_key, iv, ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len);
    if (ret != 1) {
        fprintf(stderr, "SM4 解密失败。\n");
        free(ciphertext);
        free(decryptedtext);
        return EXIT_FAILURE;
    }
    // 添加字符串终止符
    decryptedtext[decryptedtext_len] = '\0';
    printf("解密后的明文: %s\n\n", decryptedtext);

    // 3. 使用发送方的 SM2 公钥验证签名
    SM2_SIGN_CTX verify_ctx;
    ret = sm2_verify_init(&verify_ctx, &sender_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH);
    if (ret != 1) {
        fprintf(stderr, "SM2 验证初始化失败。\n");
        free(ciphertext);
        free(decryptedtext);
        return EXIT_FAILURE;
    }
    ret = sm2_verify_update(&verify_ctx, (const uint8_t *)plaintext, plaintext_len);
    if (ret != 1) {
        fprintf(stderr, "SM2 验证更新失败。\n");
        free(ciphertext);
        free(decryptedtext);
        return EXIT_FAILURE;
    }
    ret = sm2_verify_finish(&verify_ctx, signature, signature_len);
    if (ret == 1) {
        printf("签名验证成功。\n");
    } else {
        printf("签名验证失败。\n");
    }

    /* 清理内存 */
    free(ciphertext);
    free(decryptedtext);

    return EXIT_SUCCESS;
}

