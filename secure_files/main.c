#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define NONCE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define TAG crypto_aead_xchacha20poly1305_ietf_ABYTES
#define WRAPPED (NONCE + KEY + TAG)


static void die(const char *msg)
{
    fprintf(stderr, "secure_files: %s\n", msg);
    exit(EXIT_FAILURE);
}

static int wrap(unsigned char output_buffer[WRAPPED],
                const unsigned char plaintext_key[KEY],
                const unsigned char wrapping_key[KEY],
                const unsigned char *additional_data,
                size_t additional_data_len) 
{
    randombytes_buf(output_buffer, NONCE);
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
        output_buffer + NONCE, NULL,
        plaintext_key, KEY,
        additional_data, additional_data_len,
        NULL, output_buffer, wrapping_key);
}

static int unwrap(unsigned char plaintext_key[KEY], const unsigned char wrapped_key[WRAPPED],
                  const unsigned char wrapping_key[KEY], const unsigned char *additional_data, size_t additional_data_len)
{
    int return_code = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext_key, NULL, NULL,
        wrapped_key + NONCE, KEY + TAG,
        additional_data, additional_data_len,
        wrapped_key, wrapping_key);
    
    if (return_code != 0) {
        sodium_memzero(plaintext_key, KEY);
    }
    return return_code;
}


#define CHECK(cond, msg) do { if (!(cond)) die(msg); } while (0)
 
#define NONCE_TRIALS 256
 
static const unsigned char AD[] = "key-id:1";
static const unsigned char OTHER_AD[] = "key-id:2";
#define AD_LEN (sizeof AD)
#define OTHER_AD_LEN (sizeof OTHER_AD)
 
struct fixture {
    unsigned char plaintext_key[KEY];
    unsigned char wrapping_key[KEY];
    unsigned char wrapped[WRAPPED];
};
 
static void fixture_init(struct fixture *f)
{
    randombytes_buf(f->plaintext_key, KEY);
    randombytes_buf(f->wrapping_key, KEY);
    CHECK(wrap(f->wrapped, f->plaintext_key, f->wrapping_key, AD, AD_LEN) == 0,
          "fixture: wrap failed");
}
 
static void test_roundtrip(const struct fixture *f)
{
    unsigned char recovered[KEY];
    unsigned char wrapped_no_ad[WRAPPED];
 
    memset(recovered, 0xAA, KEY);
    CHECK(unwrap(recovered, f->wrapped, f->wrapping_key, AD, AD_LEN) == 0,
          "roundtrip: unwrap failed");
    CHECK(sodium_memcmp(recovered, f->plaintext_key, KEY) == 0,
          "roundtrip: key mismatch");
 
    CHECK(wrap(wrapped_no_ad, f->plaintext_key, f->wrapping_key, NULL, 0) == 0,
          "roundtrip: wrap with empty AD failed");
    memset(recovered, 0xAA, KEY);
    CHECK(unwrap(recovered, wrapped_no_ad, f->wrapping_key, NULL, 0) == 0,
          "roundtrip: unwrap with empty AD failed");
    CHECK(sodium_memcmp(recovered, f->plaintext_key, KEY) == 0,
          "roundtrip: key mismatch with empty AD");
 
    sodium_memzero(recovered, sizeof recovered);
}

static void test_bit_flips(const struct fixture *f)
{
    unsigned char tampered[WRAPPED];
    unsigned char recovered[KEY];
 
    for (size_t i = 0; i < WRAPPED; i++) {
        for (unsigned bit = 0; bit < 8; bit++) {
            memcpy(tampered, f->wrapped, WRAPPED);
            tampered[i] ^= (unsigned char) (1u << bit);
 
            memset(recovered, 0xAA, KEY);
            CHECK(unwrap(recovered, tampered, f->wrapping_key, AD, AD_LEN) != 0,
                  "bit flip: tampered blob accepted");
            CHECK(sodium_is_zero(recovered, KEY) == 1,
                  "bit flip: output not zeroed on failure");
        }
    }
 
    sodium_memzero(recovered, sizeof recovered);
}
 
static void test_wrong_key(const struct fixture *f)
{
    unsigned char wrong_key[KEY];
    unsigned char recovered[KEY];
 
    for (size_t i = 0; i < KEY; i++) {
        memcpy(wrong_key, f->wrapping_key, KEY);
        wrong_key[i] ^= 1;
        memset(recovered, 0xAA, KEY);
        CHECK(unwrap(recovered, f->wrapped, wrong_key, AD, AD_LEN) != 0,
              "wrong key: near-miss key accepted");
        CHECK(sodium_is_zero(recovered, KEY) == 1,
              "wrong key: output not zeroed on failure");
    }
 
    randombytes_buf(wrong_key, KEY);
    CHECK(unwrap(recovered, f->wrapped, wrong_key, AD, AD_LEN) != 0,
          "wrong key: unrelated key accepted");
 
    sodium_memzero(wrong_key, sizeof wrong_key);
    sodium_memzero(recovered, sizeof recovered);
}

static void test_ad_mismatch(const struct fixture *f)
{
    unsigned char recovered[KEY];
    unsigned char wrapped_no_ad[WRAPPED];
 
    CHECK(unwrap(recovered, f->wrapped, f->wrapping_key, OTHER_AD, OTHER_AD_LEN) != 0,
          "AD: different AD accepted");
    CHECK(unwrap(recovered, f->wrapped, f->wrapping_key, AD, AD_LEN - 1) != 0,
          "AD: truncated AD accepted");
    CHECK(unwrap(recovered, f->wrapped, f->wrapping_key, NULL, 0) != 0,
          "AD: missing AD accepted");
 
    CHECK(wrap(wrapped_no_ad, f->plaintext_key, f->wrapping_key, NULL, 0) == 0,
          "AD: wrap with empty AD failed");
    CHECK(unwrap(recovered, wrapped_no_ad, f->wrapping_key, AD, AD_LEN) != 0,
          "AD: AD supplied for a blob wrapped without AD was accepted");
 
    sodium_memzero(recovered, sizeof recovered);
}
 
static void test_nonce_fresh(const struct fixture *f)
{
    unsigned char blobs[NONCE_TRIALS][WRAPPED];
 
    for (size_t i = 0; i < NONCE_TRIALS; i++) {
        CHECK(wrap(blobs[i], f->plaintext_key, f->wrapping_key, AD, AD_LEN) == 0,
              "nonce: wrap failed");
    }
    for (size_t i = 0; i < NONCE_TRIALS; i++) {
        for (size_t j = i + 1; j < NONCE_TRIALS; j++) {
            CHECK(memcmp(blobs[i], blobs[j], NONCE) != 0,
                  "nonce: repeated nonce");
            CHECK(memcmp(blobs[i] + NONCE, blobs[j] + NONCE, KEY + TAG) != 0,
                  "nonce: repeated ciphertext");
        }
    }
}
 
static void selftest(void)
{
    struct fixture f;
 
    fixture_init(&f);
    test_roundtrip(&f);
    test_bit_flips(&f);
    test_wrong_key(&f);
    test_ad_mismatch(&f);
    test_nonce_fresh(&f);
    sodium_memzero(&f, sizeof f);
}

int main(void)
{
    if (sodium_init() < 0) {
        die("libsodium failed to initialise");
    }
    selftest();
    puts("selftest ok");
    return 0;
}