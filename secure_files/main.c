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

#define PATH_SIZE 1024        // longest handleable path in chars
#define PASSPHRASE_SIZE 256   // passphrase buffer size
#define MAXIMUM_FILE_SIZE (1024UL * 1024UL * 1024UL)  // 1 GiB

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

static void encrypt_file(const char *const username, const char *const file_path)
{
    (void)username;
    (void)file_path;
    shutdown("encrypt is not implemented yet");
}

static void decrypt_file(const char *const username, const char *const file_path)
{
    (void)username;
    (void)file_path;
    shutdown("decrypt is not implemented yet");
}

static void shred_file(const char *const username, const char *const file_path)
{
    (void)username;
    (void)file_path;
    shutdown("shred is not implemented yet");
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
