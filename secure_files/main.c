#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define NONCE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define TAG crypto_aead_xchacha20poly1305_ietf_ABYTES
#define WRAPPED (NONCE + KEY + TAG)

#define SALT crypto_pwhash_SALTBYTES
#define ID 16
#define MAGIC 4
#define HEAD (MAGIC + ID)
#define PATHLEN 1024
#define PASSLEN 256
#define USERLEN 32


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

/* ---- CLI -------------------------------------------------------------
 * Store (SFE_HOME, else ~/.secure_files):
 *   <user>.profile          salt | wrapped MEK
 *   <user>.keys/<id>.key    wrapped DEK of one file (deleting it = shred)
 * Encrypted file: "SFEF" | id | nonce | ciphertext+tag
 */

static const unsigned char PROFILE_AD[] = "SFEP";

static void check_user(const char *user)
{
    size_t n = strlen(user);

    CHECK(n >= 1 && n <= USERLEN, "user name must be 1-32 characters");
    for (size_t i = 0; i < n; i++) {
        char c = user[i];
        CHECK((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-',
              "user name may only contain a-z, 0-9, _ and -");
    }
}

static void check_path(const char *path)
{
    size_t n = strlen(path);

    CHECK(n >= 1 && n < PATHLEN - 8, "invalid file path length");
}

static void make_path(char *out, const char *fmt, const char *a, const char *b)
{
    int n = snprintf(out, PATHLEN, fmt, a, b);

    CHECK(n > 0 && n < PATHLEN, "path too long");
}

static const char *store_dir(void)
{
    static char dir[PATHLEN];
    const char *env = getenv("SFE_HOME");

    if (env != NULL && *env != '\0') {
        return env;
    }
    env = getenv("HOME");
    CHECK(env != NULL, "HOME is not set");
    make_path(dir, "%s/%s", env, ".secure_files");
    return dir;
}

static void profile_path(char *out, const char *user)
{
    make_path(out, "%s/%s.profile", store_dir(), user);
}

static void keys_dir(char *out, const char *user)
{
    make_path(out, "%s/%s.keys", store_dir(), user);
}

static void key_path(char *out, const char *user, const unsigned char *id)
{
    char dir[PATHLEN];
    char hex[ID * 2 + 1];

    sodium_bin2hex(hex, sizeof hex, id, ID);
    keys_dir(dir, user);
    make_path(out, "%s/%s.key", dir, hex);
}

/* Reads a regular file into memory; NULL if it is missing or not a regular file. */
static unsigned char *read_file(const char *path, size_t *len)
{
    struct stat st;
    FILE *f;
    unsigned char *buf;

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || (f = fopen(path, "rb")) == NULL) {
        return NULL;
    }
    *len = (size_t) st.st_size;
    buf = malloc(*len + 1);
    if (buf == NULL || fread(buf, 1, *len, f) != *len) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    return buf;
}

/* Checked before prompting, so a refused run neither asks for a passphrase nor leaves a key behind. */
static void refuse_existing(const char *path)
{
    CHECK(access(path, F_OK) != 0, "output file already exists, refusing to overwrite");
}

/* Creates a new file; "x" makes the creation itself exclusive. */
static void create_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wbx");

    CHECK(f != NULL, "cannot create output file (does it already exist?)");
    CHECK(fwrite(buf, 1, len, f) == len && fclose(f) == 0, "cannot write output file");
}

static void read_password(const char *prompt, char *buf, size_t cap)
{
    struct termios old, quiet;
    int tty = isatty(STDIN_FILENO);

    fputs(prompt, stderr);
    if (tty) {
        tcgetattr(STDIN_FILENO, &old);
        quiet = old;
        quiet.c_lflag &= ~(tcflag_t) ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
    }
    char *got = fgets(buf, (int) cap, stdin);
    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        fputc('\n', stderr);
    }
    CHECK(got != NULL, "no passphrase given");
    buf[strcspn(buf, "\r\n")] = '\0';
    CHECK(buf[0] != '\0', "empty passphrase");
}

static void derive_kek(unsigned char kek[KEY], const char *pass, const unsigned char *salt)
{
    CHECK(crypto_pwhash(kek, KEY, pass, strlen(pass), salt,
                        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                        crypto_pwhash_ALG_ARGON2ID13) == 0,
          "key derivation failed (out of memory?)");
}

/* Prompts for the passphrase and unlocks the user's master key. */
static void load_mek(unsigned char mek[KEY], const char *user)
{
    char path[PATHLEN], pass[PASSLEN];
    unsigned char kek[KEY];
    size_t len;
    unsigned char *profile;

    profile_path(path, user);
    profile = read_file(path, &len);
    CHECK(profile != NULL && len == SALT + WRAPPED, "no such profile (run init first)");
    read_password("Passphrase: ", pass, sizeof pass);
    derive_kek(kek, pass, profile);
    CHECK(unwrap(mek, profile + SALT, kek, PROFILE_AD, sizeof PROFILE_AD) == 0, "wrong passphrase");
    sodium_memzero(kek, sizeof kek);
    sodium_memzero(pass, sizeof pass);
    free(profile);
}

static unsigned char *load_enc(const char *file, size_t *len)
{
    unsigned char *enc = read_file(file, len);

    CHECK(enc != NULL, "cannot read encrypted file");
    CHECK(*len >= HEAD + NONCE + TAG && memcmp(enc, "SFEF", MAGIC) == 0, "not an encrypted file");
    return enc;
}

static void cmd_init(const char *user)
{
    char path[PATHLEN], dir[PATHLEN], pass[PASSLEN], again[PASSLEN];
    unsigned char profile[SALT + WRAPPED], mek[KEY], kek[KEY];

    profile_path(path, user);
    refuse_existing(path);
    read_password("New passphrase: ", pass, sizeof pass);
    read_password("Repeat passphrase: ", again, sizeof again);
    CHECK(strcmp(pass, again) == 0, "passphrases do not match");

    randombytes_buf(profile, SALT);
    randombytes_buf(mek, KEY);
    derive_kek(kek, pass, profile);
    CHECK(wrap(profile + SALT, mek, kek, PROFILE_AD, sizeof PROFILE_AD) == 0, "wrap failed");

    mkdir(store_dir(), 0700);
    keys_dir(dir, user);
    mkdir(dir, 0700);
    create_file(path, profile, sizeof profile);

    sodium_memzero(mek, sizeof mek);
    sodium_memzero(kek, sizeof kek);
    sodium_memzero(pass, sizeof pass);
    sodium_memzero(again, sizeof again);
    printf("initialised profile '%s'\n", user);
}

static void cmd_encrypt(const char *user, const char *file)
{
    char out_path[PATHLEN], rec_path[PATHLEN];
    unsigned char mek[KEY], dek[KEY], head[HEAD], record[WRAPPED];
    size_t len, total;
    unsigned char *plain, *enc;

    plain = read_file(file, &len);
    CHECK(plain != NULL, "cannot read input file (missing or not a regular file)");
    make_path(out_path, "%s%s", file, ".enc");
    refuse_existing(out_path);
    load_mek(mek, user);

    memcpy(head, "SFEF", MAGIC);
    randombytes_buf(head + MAGIC, ID);
    randombytes_buf(dek, KEY);

    total = HEAD + NONCE + len + TAG;
    enc = malloc(total);
    CHECK(enc != NULL, "out of memory");
    memcpy(enc, head, HEAD);
    randombytes_buf(enc + HEAD, NONCE);
    crypto_aead_xchacha20poly1305_ietf_encrypt(enc + HEAD + NONCE, NULL, plain, len, head, HEAD, NULL,
                                               enc + HEAD, dek);

    CHECK(wrap(record, dek, mek, head + MAGIC, ID) == 0, "wrap failed");
    key_path(rec_path, user, head + MAGIC);
    create_file(rec_path, record, sizeof record);
    create_file(out_path, enc, total);

    sodium_memzero(mek, sizeof mek);
    sodium_memzero(dek, sizeof dek);
    free(plain);
    free(enc);
    printf("encrypted -> %s\n", out_path);
}

static void cmd_decrypt(const char *user, const char *file)
{
    char out_path[PATHLEN], rec_path[PATHLEN];
    unsigned char mek[KEY], dek[KEY];
    size_t len, rlen, flen = strlen(file), clen;
    unsigned char *enc, *record, *plain;
    unsigned long long plen;

    CHECK(flen > 4 && strcmp(file + flen - 4, ".enc") == 0, "input file must end in .enc");
    enc = load_enc(file, &len);
    snprintf(out_path, PATHLEN, "%.*s", (int) (flen - 4), file);
    refuse_existing(out_path);
    load_mek(mek, user);

    key_path(rec_path, user, enc + MAGIC);
    record = read_file(rec_path, &rlen);
    CHECK(record != NULL && rlen == WRAPPED && unwrap(dek, record, mek, enc + MAGIC, ID) == 0,
          "key record missing (shredded?) or corrupt");

    clen = len - HEAD - NONCE;
    plain = malloc(clen);
    CHECK(plain != NULL, "out of memory");
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(plain, &plen, NULL, enc + HEAD + NONCE, clen, enc, HEAD,
                                                     enc + HEAD, dek) == 0,
          "file is corrupt or has been modified");
    create_file(out_path, plain, (size_t) plen);

    sodium_memzero(mek, sizeof mek);
    sodium_memzero(dek, sizeof dek);
    sodium_memzero(plain, clen);
    free(record);
    free(plain);
    free(enc);
    printf("decrypted -> %s\n", out_path);
}

static void cmd_shred(const char *user, const char *file)
{
    char rec_path[PATHLEN];
    unsigned char mek[KEY];
    size_t len;
    unsigned char *enc = load_enc(file, &len);

    load_mek(mek, user);
    key_path(rec_path, user, enc + MAGIC);
    CHECK(remove(rec_path) == 0, "key record not found (already shredded?)");
    CHECK(remove(file) == 0, "key destroyed, but could not delete the encrypted file");

    sodium_memzero(mek, sizeof mek);
    free(enc);
    printf("shredded %s\n", file);
}

static void usage(void)
{
    fputs("usage: secure_files init    --user NAME\n"
          "       secure_files encrypt --user NAME FILE\n"
          "       secure_files decrypt --user NAME FILE.enc\n"
          "       secure_files shred   --user NAME FILE.enc\n"
          "       secure_files selftest\n",
          stderr);
    exit(2);
}

int main(int argc, char **argv)
{
    const char *cmd, *user = NULL, *file = NULL;

    if (sodium_init() < 0) {
        die("libsodium failed to initialise");
    }
    if (argc < 2) {
        usage();
    }
    cmd = argv[1];

    if (strcmp(cmd, "selftest") == 0 && argc == 2) {
        selftest();
        puts("selftest ok");
        return 0;
    }

    /* strict parsing: exactly one --user NAME and at most one FILE, nothing else */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--user") == 0 && i + 1 < argc && user == NULL) {
            user = argv[++i];
        } else if (argv[i][0] != '-' && file == NULL) {
            file = argv[i];
        } else {
            usage();
        }
    }
    if (user == NULL) {
        usage();
    }
    check_user(user);
    if (file != NULL) {
        check_path(file);
    }

    if (strcmp(cmd, "init") == 0 && file == NULL) {
        cmd_init(user);
    } else if (strcmp(cmd, "encrypt") == 0 && file != NULL) {
        cmd_encrypt(user, file);
    } else if (strcmp(cmd, "decrypt") == 0 && file != NULL) {
        cmd_decrypt(user, file);
    } else if (strcmp(cmd, "shred") == 0 && file != NULL) {
        cmd_shred(user, file);
    } else {
        usage();
    }
    return 0;
}