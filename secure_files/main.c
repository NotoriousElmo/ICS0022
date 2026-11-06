#define _POSIX_C_SOURCE 200809L

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>

#define KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define NONCE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define TAG crypto_aead_xchacha20poly1305_ietf_ABYTES
#define WRAPPED (NONCE + KEY + TAG)
#define SALT crypto_pwhash_SALTBYTES
#define PROFILE_SIZE (SALT + WRAPPED)

#define STREAM_HEADER crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define STREAM_TAG crypto_secretstream_xchacha20poly1305_ABYTES
#define STREAM_FINAL crypto_secretstream_xchacha20poly1305_TAG_FINAL
#define MAGIC "SF01"
#define LEN_OF_MAGIC (sizeof(MAGIC) - 1)
#define FILE_ID_SIZE 16
#define FILE_ID_AT LEN_OF_MAGIC
#define STREAM_AT (FILE_ID_AT + FILE_ID_SIZE)
#define HEADER_SIZE (STREAM_AT + STREAM_HEADER)

#define PATH_SIZE 1024        // longest handleable path in chars
#define PASSPHRASE_SIZE 256   // passphrase buffer size
#define MAXIMUM_FILE_SIZE (1024UL * 1024UL * 1024UL)  // 1 GiB
#define CHUNK_SIZE 65536
#define MAXIMUM_ENCRYPTED_SIZE (MAXIMUM_FILE_SIZE + HEADER_SIZE + STREAM_TAG * (MAXIMUM_FILE_SIZE / CHUNK_SIZE + 1))  // largest file encrypt can produce

static _Noreturn void shutdown(const char *const msg)
{
    fprintf(stderr, "secure_files: %s\n", msg);
    exit(EXIT_FAILURE);
}

static _Noreturn void shutdown_with_system_error(const char *const msg)
{
    fprintf(stderr, "secure_files: %s; with error: %s\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

static int wrap_key(unsigned char output_buffer[WRAPPED],
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

__attribute__((unused))
static int unwrap_key(unsigned char plaintext_key[KEY],
                      const unsigned char wrapped_key[WRAPPED],
                      const unsigned char wrapping_key[KEY],
                      const unsigned char *additional_data,
                      size_t additional_data_len)
{
    const int return_code = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext_key, NULL, NULL,
        wrapped_key + NONCE, KEY + TAG,
        additional_data, additional_data_len,
        wrapped_key, wrapping_key);

    if (return_code != 0) {
        sodium_memzero(plaintext_key, KEY);
    }
    return return_code;
}

static void require_priv_dir(const char *const dir_path)
{
    struct stat dir_status;

    if (lstat(dir_path, &dir_status) != 0 || !S_ISDIR(dir_status.st_mode)) {
        shutdown("store or key directory is missing or not a directory");
    }

    if (dir_status.st_uid != geteuid() || (dir_status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        shutdown("store or key directory must be owned by you with mode 0700");
    }
}

static void create_priv_dir(const char *const dir_path)
{
    if (mkdir(dir_path, 0700) != 0 && errno != EEXIST) {
        shutdown_with_system_error("cannot create private directory");
    }

    require_priv_dir(dir_path);
}

static const char *store_directory(void)
{
    static char store_dir[PATH_SIZE];
    char project_dir[PATH_SIZE];

    if (getcwd(project_dir, sizeof project_dir) == NULL) {
        shutdown_with_system_error("cannot determine the project directory");
    }

    const int written_chars = snprintf(store_dir, sizeof store_dir, "%s/.secure_files", project_dir);

    if (written_chars < 0 || (size_t)written_chars >= sizeof store_dir) {
        shutdown("project directory path is too long");
    }

    return store_dir;
}

static void build_keys_dir_path(char *const dir_path, const char *const username)
{
    const int written_chars = snprintf(dir_path, PATH_SIZE, "%s/%s.keys", store_directory(), username);

    if (written_chars < 0 || written_chars >= PATH_SIZE) {
        shutdown("keys directory path is too long");
    }
}

static void build_profile_path(char *const profile_path, const char *const username)
{
    const int written_chars = snprintf(profile_path, PATH_SIZE, "%s/%s.profile", store_directory(), username);

    if (written_chars < 0 || written_chars >= PATH_SIZE) {
        shutdown("profile path is too long");
    }
}

static void require_file_missing(const char *const file_path, const char *const message)
{
    if (access(file_path, F_OK) == 0) {
        shutdown(message);
    }
}

static void read_password(const char *const prompt, char *const password, const size_t password_size)
{
    struct termios original_settings;
    struct termios silent_settings;
    const bool is_terminal = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original_settings) == 0;

    if (is_terminal) {
        silent_settings = original_settings;
        silent_settings.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent_settings);
    }

    fputs(prompt, stderr);

    const char *const line = fgets(password, (int)password_size, stdin);

    if (is_terminal) {
        tcsetattr(STDIN_FILENO, TCSANOW, &original_settings);
        fputc('\n', stderr);
    }

    if (line == NULL) {
        sodium_memzero(password, password_size);
        shutdown("no password given");
    }

    const size_t line_len = strcspn(password, "\r\n");

    if (password[line_len] == '\0' && line_len == password_size - 1) {
        sodium_memzero(password, password_size);
        shutdown("password is too long");
    }

    password[line_len] = '\0';
}

static void derive_key_encryption_key(unsigned char *const key_encryption_key,
                                      const char *const password,
                                      const unsigned char *const salt)
{
    const int return_code = crypto_pwhash(
        key_encryption_key, KEY,
        password, strlen(password),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13);

    if (return_code != 0) {
        shutdown("key derivation failed");
    }
}

static int write_all(const int file_descriptor, const unsigned char *const contents, const size_t contents_len)
{
    size_t written_len = 0;

    while (written_len < contents_len) {
        const ssize_t chunk_len = write(file_descriptor, contents + written_len, contents_len - written_len);

        if (chunk_len < 0 && errno == EINTR) {
            continue;
        }

        if (chunk_len <= 0) {
            return -1;
        }

        written_len += (size_t)chunk_len;
    }

    return 0;
}

static int write_new_file(const char *const file_path, const unsigned char *const contents, const size_t contents_len)
{
    const int file_descriptor = open(file_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

    if (file_descriptor < 0) {
        return -1;
    }

    if (write_all(file_descriptor, contents, contents_len) != 0 || fsync(file_descriptor) != 0) {
        const int error_code = errno;

        close(file_descriptor);
        unlink(file_path);
        errno = error_code;
        return -1;
    }

    if (close(file_descriptor) != 0) {
        const int error_code = errno;

        unlink(file_path);
        errno = error_code;
        return -1;
    }

    return 0;
}

static void initialise_profile(const char *const username)
{
    char keys_dir_path[PATH_SIZE];
    char profile_file_path[PATH_SIZE];
    char password[PASSPHRASE_SIZE];
    char repeated_password[PASSPHRASE_SIZE];
    unsigned char profile[PROFILE_SIZE];
    unsigned char master_key[KEY];
    unsigned char key_encryption_key[KEY];

    create_priv_dir(store_directory());

    build_keys_dir_path(keys_dir_path, username);
    create_priv_dir(keys_dir_path);

    build_profile_path(profile_file_path, username);
    require_file_missing(profile_file_path, "profile already exists");

    read_password("Enter password: ", password, sizeof password);
    read_password("Repeat password: ", repeated_password, sizeof repeated_password);

    if (strcmp(password, repeated_password) != 0) {
        shutdown("passwords don't match");
    }

    if (strlen(password) < 12) {
        shutdown("password is too short (min 12 chars)");
    }

    // profile layout: [salt | nonce | wrapped master key | tag]
    randombytes_buf(profile, SALT);
    randombytes_buf(master_key, KEY);

    derive_key_encryption_key(key_encryption_key, password, profile);

    // salt is bound as additional data so it cannot be swapped undetected
    if (wrap_key(profile + SALT, master_key, key_encryption_key, profile, SALT) != 0) {
        shutdown("couldn't wrap the master key");
    }

    if (write_new_file(profile_file_path, profile, sizeof profile) != 0) {
        shutdown_with_system_error("cannot create profile");
    }

    sodium_memzero(password, sizeof password);
    sodium_memzero(repeated_password, sizeof repeated_password);
    sodium_memzero(key_encryption_key, sizeof key_encryption_key);
    sodium_memzero(master_key, sizeof master_key);

    printf("initialised profile\n");
}

static bool is_valid_username(const char *const username)
{
    const char *const allowed_characters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    const size_t username_len = strlen(username);

    return username_len != 0 && username_len <= 32
        && strspn(username, allowed_characters) == username_len;
}

static ssize_t read_full(const int file_descriptor, unsigned char *const buffer, const size_t buffer_length)
{
    size_t read_len = 0;
    while (read_len < buffer_length) {
        const ssize_t chunk_length = read(file_descriptor, buffer + read_len, buffer_length - read_len);
        if (chunk_length < 0 && errno == EINTR) {
            continue;
        }
        if (chunk_length < 0) {
            return -1;
        }
        if (chunk_length == 0) {
            break;
        }
        read_len += (size_t)chunk_length;
    }
    return (ssize_t)read_len;
}

static const char *encrypt_stream(const int input_file_descriptor, const int output_file_descriptor, crypto_secretstream_xchacha20poly1305_state *const state) 
{
    unsigned char plain[CHUNK_SIZE];
    unsigned char cipher[CHUNK_SIZE + STREAM_TAG];
    unsigned long long cipher_len;
    const char *error = NULL;
    bool is_last = false;

    while (!is_last && error == NULL) {
        const ssize_t plain_len = read_full(input_file_descriptor, plain, sizeof plain);

        if (plain_len < 0) {
            error = "read_failed";
            break;
        }
        is_last = (size_t)plain_len < sizeof plain;

        if (crypto_secretstream_xchacha20poly1305_push(state, cipher, &cipher_len, plain, (unsigned long long)plain_len, NULL, 0, is_last ? STREAM_FINAL : 0) != 0) {
            error = "encryption failed";
        } else if (write_all(output_file_descriptor, cipher, (size_t)cipher_len) != 0) {
            error = "write failed";
        }
    }
    sodium_memzero(plain, sizeof plain);
    return error;
}

static int open_input_file(const char *const file_path, const unsigned long long maximum_size) {
    struct stat file_status;
    if (strlen(file_path) == 0 || strlen(file_path) >= PATH_SIZE) {
        shutdown("invalid file path");
    }
    const int file_descriptor = open(file_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (file_descriptor < 0) {
        shutdown_with_system_error("cannot open input file");
    }
    if (fstat(file_descriptor, &file_status) != 0 || !S_ISREG(file_status.st_mode)) {
        shutdown("input is not a regular file");
    }
    if ((unsigned long long)file_status.st_size > maximum_size) {
        shutdown("input file is too large");
    }
    return file_descriptor;
}

static void build_the_encrypted_path(char *const encrypted_path, const char *const file_path) {
    const int written_chars = snprintf(encrypted_path, PATH_SIZE, "%s%s", file_path, ".enc");
    if (written_chars < 0 || written_chars >= PATH_SIZE) {
        shutdown("output path is too long");
    }
}

static void build_key_path(char *const key_path, const char *const username, const unsigned char *const file_id) {
    char keys_dir_path[PATH_SIZE];
    char file_id_hex[FILE_ID_SIZE * 2 + 1];
    build_keys_dir_path(keys_dir_path, username);
    require_priv_dir(store_directory());
    require_priv_dir(keys_dir_path);
    sodium_bin2hex(file_id_hex, sizeof file_id_hex, file_id, FILE_ID_SIZE);

    const int written_chars = snprintf(key_path, PATH_SIZE, "%s/%s%s", keys_dir_path, file_id_hex, ".key");
    
    if (written_chars < 0 || written_chars >= PATH_SIZE) {
        shutdown("key path is too long");
    }
}

static void load_master_key(const char *const username, unsigned char master_key[KEY])
{
    char profile_path[PATH_SIZE];
    char password[PASSPHRASE_SIZE];
    unsigned char profile[PROFILE_SIZE];
    unsigned char key_encryption_key[KEY];

    build_profile_path(profile_path, username);

    const int profile_file_descriptor = open(profile_path, O_RDONLY | O_NOFOLLOW);

    if (profile_file_descriptor < 0) {
        shutdown_with_system_error("cannot open profile");
    }

    const ssize_t profile_length = read_full(profile_file_descriptor, profile, sizeof profile);

    close(profile_file_descriptor);

    if (profile_length != (ssize_t)sizeof profile) {
        shutdown("profile is corrupted");
    }

    read_password("Enter password: ", password, sizeof password);
    derive_key_encryption_key(key_encryption_key, password, profile);
    sodium_memzero(password, sizeof password);

    const int return_code = unwrap_key(master_key, profile + SALT, key_encryption_key, profile, SALT);
    sodium_memzero(key_encryption_key, sizeof key_encryption_key);

    if (return_code != 0) {
        shutdown("wrong password or corrupted profile");
    }
}

static void encrypt_file(const char *const username, const char *const file_path)
{
    char encrypted_path[PATH_SIZE];
    char key_path[PATH_SIZE];
    unsigned char header[HEADER_SIZE];
    unsigned char master_key[KEY];
    unsigned char file_key[KEY];
    unsigned char wrapped_key[WRAPPED];
    crypto_secretstream_xchacha20poly1305_state state;

    build_the_encrypted_path(encrypted_path, file_path);
    require_file_missing(encrypted_path, "output file already exists");

    const int input_file_descriptor = open_input_file(file_path, MAXIMUM_FILE_SIZE);

    memcpy(header, MAGIC, LEN_OF_MAGIC);
    randombytes_buf(header + FILE_ID_AT, FILE_ID_SIZE);
    randombytes_buf(file_key, KEY);
    build_key_path(key_path, username, header + FILE_ID_AT);

    load_master_key(username, master_key);

    const int init_code = crypto_secretstream_xchacha20poly1305_init_push(&state, header + STREAM_AT, file_key);
    const int wrap_code = wrap_key(wrapped_key, file_key, master_key, header, STREAM_AT);

    sodium_memzero(master_key, sizeof master_key);
    sodium_memzero(file_key, sizeof file_key);

    if (init_code != 0 || wrap_code != 0) {
        sodium_memzero(&state, sizeof state);
        shutdown("could not set up encryption");
    }

    if (write_new_file(key_path, wrapped_key, sizeof wrapped_key) != 0) {
        sodium_memzero(&state, sizeof state);
        shutdown_with_system_error("cannot store file key");
    }

    const int output_file_descriptor = open(encrypted_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

    if (output_file_descriptor < 0) {
        const int error_code = errno;

        unlink(key_path);
        sodium_memzero(&state, sizeof state);
        errno = error_code;
        shutdown_with_system_error("cannot create output file");
    }

    const char *error = write_all(output_file_descriptor, header, sizeof header) != 0 ? "write failed" : encrypt_stream(input_file_descriptor, output_file_descriptor, &state);
    sodium_memzero(&state, sizeof state);

    if (error == NULL && fsync(output_file_descriptor) != 0) {
        error = "write failed";
    }

    if (close(output_file_descriptor) != 0 && error == NULL) {
        error = "write failed";
    }

    close(input_file_descriptor);

    if (error != NULL) {
        unlink(encrypted_path);
        unlink(key_path);
        shutdown(error);
    }

    printf("encrypted to %s\n", encrypted_path);
}

static void load_wrapped_key(const char *const key_path, unsigned char wrapped_key[WRAPPED])
{
    const int key_file_descriptor = open(key_path, O_RDONLY | O_NOFOLLOW);

    if (key_file_descriptor < 0) {
        shutdown_with_system_error("cannot open file key");
    }

    const ssize_t key_length = read_full(key_file_descriptor, wrapped_key, WRAPPED);

    close(key_file_descriptor);

    if (key_length != (ssize_t)WRAPPED) {
        shutdown("file key is corrupted");
    }
}

static const char *decrypt_stream(const int input_file_descriptor, const int output_file_descriptor, crypto_secretstream_xchacha20poly1305_state *const state)
{
    unsigned char cipher[CHUNK_SIZE + STREAM_TAG];
    unsigned char plain[CHUNK_SIZE];
    unsigned long long plain_len;
    unsigned char tag;
    const char *error = NULL;
    bool is_last = false;

    while (!is_last && error == NULL) {
        const ssize_t cipher_len = read_full(input_file_descriptor, cipher, sizeof cipher);

        if (cipher_len < 0) {
            error = "read failed";
            break;
        }

        // encryption only emits a short chunk as the final one, so a short read is the end of the file
        is_last = (size_t)cipher_len < sizeof cipher;

        if ((size_t)cipher_len < STREAM_TAG) {
            error = "encrypted file is truncated";
        } else if (crypto_secretstream_xchacha20poly1305_pull(state, plain, &plain_len, &tag, cipher, (unsigned long long)cipher_len, NULL, 0) != 0) {
            error = "encrypted file is corrupted or has been modified";
        } else if (tag != (is_last ? STREAM_FINAL : 0)) {
            error = "encrypted file is truncated or malformed";
        } else if (write_all(output_file_descriptor, plain, (size_t)plain_len) != 0) {
            error = "write failed";
        }
    }
    sodium_memzero(plain, sizeof plain);

    return error;
}

static void build_decrypted_file_path(char *const decrypted_path, const char *const file_path) {
    static const char encrypted_suffix[] = ".enc";
    const size_t suffix_len = sizeof encrypted_suffix - 1;
    const int written_chars = snprintf(decrypted_path, PATH_SIZE, "%s", file_path);

    if (written_chars < 0 || written_chars >= PATH_SIZE) {
        shutdown("invalid file path");
    }

    const size_t path_len = (size_t)written_chars;

    if (path_len <= suffix_len || strcmp(decrypted_path + path_len - suffix_len, encrypted_suffix) != 0 || decrypted_path[path_len - suffix_len - 1] == '/') {
        shutdown("input file must be named NAME.enc");
    }

    decrypted_path[path_len - suffix_len] = '\0';
}

static void decrypt_file(const char *const username, const char *const file_path)
{
    char decrypted_path[PATH_SIZE];
    char key_path[PATH_SIZE];
    unsigned char header[HEADER_SIZE];
    unsigned char master_key[KEY];
    unsigned char file_key[KEY];
    unsigned char wrapped_key[WRAPPED];
    crypto_secretstream_xchacha20poly1305_state state;

    build_decrypted_file_path(decrypted_path, file_path);

    require_file_missing(decrypted_path, "decrypted file already exists");

    const int input_file_descriptor = open_input_file(file_path, MAXIMUM_ENCRYPTED_SIZE);

    const ssize_t header_length = read_full(input_file_descriptor, header, sizeof header);

    if (header_length != (ssize_t)sizeof header || memcmp(header, MAGIC, LEN_OF_MAGIC) != 0) {
        shutdown("input is not an encrypted file");
    }

    build_key_path(key_path, username, header + FILE_ID_AT);
    load_wrapped_key(key_path, wrapped_key);
    load_master_key(username, master_key);

    const int unwrap_code = unwrap_key(file_key, wrapped_key, master_key, header, STREAM_AT);    // a key file belonging to another file is rejected

    sodium_memzero(master_key, sizeof master_key);

    if (unwrap_code != 0) {
        shutdown("cannot unwrap file key, key file or header is corrupted");
    }
    const int init_code = crypto_secretstream_xchacha20poly1305_init_pull(&state, header + STREAM_AT, file_key);

    sodium_memzero(file_key, sizeof file_key);

    if (init_code != 0) {
        sodium_memzero(&state, sizeof state);
        shutdown("could not set up decryption");
    }
    const int output_file_descriptor = open(decrypted_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    
    if (output_file_descriptor < 0) {
        const int error_code = errno;
        sodium_memzero(&state, sizeof state);
        errno = error_code;
        shutdown_with_system_error("cannot create output file");
    }
    const char *error = decrypt_stream(input_file_descriptor, output_file_descriptor, &state);
    sodium_memzero(&state, sizeof state);

    if (error == NULL && fsync(output_file_descriptor) != 0) {
        error = "write failed";
    }
    if (close(output_file_descriptor) != 0 && error == NULL) {
        error = "write failed";
    }

    close(input_file_descriptor);
    if (error != NULL) {
        unlink(decrypted_path);
        shutdown(error);
    }

    printf("decrypted to %s\n", decrypted_path);
}

static int overwrite_with_random_bytes(const int file_descriptor, const unsigned long long file_length) {
    unsigned char noise[CHUNK_SIZE];
    unsigned long long remaining_length = file_length;

    while (remaining_length > 0) {
        const size_t chunk_length = remaining_length < sizeof noise ? (size_t)remaining_length : sizeof noise;

        randombytes_buf(noise, chunk_length);

        if (write_all(file_descriptor, noise, chunk_length) != 0) {
            return -1;
        }

        remaining_length -= chunk_length;
    }

    return fsync(file_descriptor);
}

static int overwrite_and_remove_file(const char *const file_path){
    struct stat file_status;
    const int file_descriptor = open(file_path, O_WRONLY | O_NOFOLLOW | O_NONBLOCK);

    if (file_descriptor < 0) {
        return -1;
    }

    if (fstat(file_descriptor, &file_status) != 0 || !S_ISREG(file_status.st_mode)) {
        close(file_descriptor);
        errno = EINVAL;
        return -1;
    }

    // overwritten before the name is removed, so the old bytes are not just left behind in free blocks
    if (overwrite_with_random_bytes(file_descriptor, (unsigned long long)file_status.st_size) != 0) {
        const int error_code = errno;

        close(file_descriptor);
        errno = error_code;
        return -1;
    }

    if (close(file_descriptor) != 0) {
        return -1;
    }

    return unlink(file_path);
}

static void shred_file(const char *const username, const char *const file_path) {
    char key_path[PATH_SIZE];
    unsigned char header[HEADER_SIZE];
    unsigned char master_key[KEY];

    const int input_file_descriptor = open_input_file(file_path, MAXIMUM_ENCRYPTED_SIZE);

    const ssize_t header_length = read_full(input_file_descriptor, header, sizeof header);

    close(input_file_descriptor);

    if (header_length != (ssize_t)sizeof header || memcmp(header, MAGIC, LEN_OF_MAGIC) != 0) {
        shutdown("input is not an encrypted file");
    }

    build_key_path(key_path, username, header + FILE_ID_AT);

    if (access(key_path, F_OK) != 0) {
        shutdown_with_system_error("cannot open file key");
    }

    load_master_key(username, master_key);
    sodium_memzero(master_key, sizeof master_key);

    if (overwrite_and_remove_file(key_path) != 0) {
        shutdown_with_system_error("cannot destroy file key");
    }

    if (overwrite_and_remove_file(file_path) != 0) {
        shutdown_with_system_error("file key destroyed, but cannot remove encrypted file");
    }

    printf("shredded %s\n", file_path);
}

int main(int argument_count, char **argument_values)
{
    static const char usage_message[] =
        "usage: secure_files init --user NAME | secure_files {encrypt|decrypt|shred} --user NAME FILE";
    const char *username = NULL;
    const char *file_path = NULL;
    const struct rlimit no_core_dumps = {0, 0};

    if (sodium_init() < 0) {
        shutdown("libsodium failed to initialise");
    }

    if (setrlimit(RLIMIT_CORE, &no_core_dumps) != 0) {
        shutdown_with_system_error("cannot disable core dumps");
    }

    if (argument_count < 2) {
        shutdown(usage_message);
    }

    const char *const command_name = argument_values[1];

    for (int argument_index = 2; argument_index < argument_count; argument_index++) {
        if (strcmp(argument_values[argument_index], "--user") == 0) {
            if (username != NULL || argument_index + 1 >= argument_count) {
                shutdown(usage_message);
            }
            argument_index++;
            username = argument_values[argument_index];
        } else if (file_path == NULL) {
            file_path = argument_values[argument_index];
        } else {
            shutdown(usage_message);
        }
    }

    if (username == NULL) {
        shutdown(usage_message);
    }

    if (!is_valid_username(username)) {
        shutdown("user name must be 1-32 characters of A-Z a-z 0-9 _ -");
    }

    if (strcmp(command_name, "init") == 0 && file_path == NULL) {
        initialise_profile(username);
    } else if (strcmp(command_name, "encrypt") == 0 && file_path != NULL) {
        encrypt_file(username, file_path);
    } else if (strcmp(command_name, "decrypt") == 0 && file_path != NULL) {
        decrypt_file(username, file_path);
    } else if (strcmp(command_name, "shred") == 0 && file_path != NULL) {
        shred_file(username, file_path);
    } else {
        shutdown(usage_message);
    }

    return 0;
}
