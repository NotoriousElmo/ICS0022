#!/bin/bash
set -u

BINARY_PATH="$(cd "$(dirname "$0")" && pwd)/secure_files/secure_files"
WORK_DIRECTORY=$(mktemp -d)

cd "$WORK_DIRECTORY"
if [ $? -ne 0 ]; then
    echo "FAIL: Could not enter working directory"
    exit 1
fi

USER_NAME=$(whoami)
failure_count=0

pass_test() {
    local message="$1"
    echo "PASS: ${message}"
}

fail_test() {
    local message="$1"
    echo "FAIL: ${message}"
    failure_count=$((failure_count + 1))
}

assert_failure_with_password() {
    local test_description="$1"
    local password_input="$2"
    shift 2

    local raw_output
    raw_output=$(echo -e "$password_input" | "$BINARY_PATH" "$@" 2>&1)
    local exit_code=$?

    local cleaned_output
    cleaned_output=$(echo "$raw_output" | sed 's/Enter password: //g; s/Repeat password: //g' | tr -d '\r\n')

    if [ $exit_code -eq 0 ]; then
        fail_test "${test_description} exited with success but should have failed"
    elif [ "$cleaned_output" != "secure_files: operation failed" ]; then
        fail_test "${test_description} gave wrong terminal output: ${cleaned_output}"
    else
        pass_test "${test_description}"
    fi
}

assert_failure_no_password() {
    local test_description="$1"
    shift 1

    local raw_output
    raw_output=$("$BINARY_PATH" "$@" 2>&1)
    local exit_code=$?

    local cleaned_output
    cleaned_output=$(echo "$raw_output" | sed 's/Enter password: //g; s/Repeat password: //g' | tr -d '\r\n')

    if [ $exit_code -eq 0 ]; then
        fail_test "${test_description} exited with success but should have failed"
    elif [ "$cleaned_output" != "secure_files: operation failed" ]; then
        fail_test "${test_description} gave wrong terminal output: ${cleaned_output}"
    else
        pass_test "${test_description}"
    fi
}

# Password validation tests
assert_failure_with_password "Fails: Initialise with 11 character password" "12345678901\n12345678901" init --user "$USER_NAME"

assert_failure_with_password "Fails: Initialise with mismatched passwords" "TestPass1234\nTestPass1235" init --user "$USER_NAME"

echo -e "123456789012\n123456789012" | "$BINARY_PATH" init --user "$USER_NAME" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Initialise with 12 character password"
else
    pass_test "Succeeds: Initialise with 12 character password"
fi
rm -rf .secure_files

echo -e "1234567890123\n1234567890123" | "$BINARY_PATH" init --user "$USER_NAME" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Initialise with 13 character password"
else
    pass_test "Succeeds: Initialise with 13 character password"
fi
rm -rf .secure_files

# the password buffer is 256 bytes: 254 characters + newline + NUL is the longest accepted input
password_254=$(printf "%0254d" 0)
echo -e "${password_254}\n${password_254}" | "$BINARY_PATH" init --user "$USER_NAME" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Initialise with 254 character password"
else
    pass_test "Succeeds: Initialise with 254 character password"
fi
rm -rf .secure_files

password_255=$(printf "%0255d" 0)
assert_failure_with_password "Fails: Initialise with 255 character password" "${password_255}\n${password_255}" init --user "$USER_NAME"
rm -rf .secure_files

# Permanent initialisation for remaining tests
echo -e "TestPass1234\nTestPass1234" | "$BINARY_PATH" init --user "$USER_NAME" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Initialise main profile"
else
    pass_test "Succeeds: Initialise main profile"
fi

# Test a zero-byte file
head -c 0 /dev/urandom > "file_0"
cp "file_0" ".original_0"

echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "file_0" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Encrypt file of size 0"
else
    pass_test "Succeeds: Encrypt file of size 0"
fi

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "file_0.enc" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Decrypt file of size 0"
else
    pass_test "Succeeds: Decrypt file of size 0"
fi

cmp -s "file_0" ".original_0"
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Match decrypted file of size 0"
else
    pass_test "Succeeds: Match decrypted file of size 0"
fi

# Test a 1-byte file
head -c 1 /dev/urandom > "file_1"
cp "file_1" ".original_1"

echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "file_1" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Encrypt file of size 1"
else
    pass_test "Succeeds: Encrypt file of size 1"
fi

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "file_1.enc" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Decrypt file of size 1"
else
    pass_test "Succeeds: Decrypt file of size 1"
fi

cmp -s "file_1" ".original_1"
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Match decrypted file of size 1"
else
    pass_test "Succeeds: Match decrypted file of size 1"
fi

# Test exactly one 64 KiB chunk
head -c 65536 /dev/urandom > "file_65536"
cp "file_65536" ".original_65536"

echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "file_65536" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Encrypt file of size 65536"
else
    pass_test "Succeeds: Encrypt file of size 65536"
fi

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "file_65536.enc" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Decrypt file of size 65536"
else
    pass_test "Succeeds: Decrypt file of size 65536"
fi

cmp -s "file_65536" ".original_65536"
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Match decrypted file of size 65536"
else
    pass_test "Succeeds: Match decrypted file of size 65536"
fi

# Test one chunk plus 1 byte
head -c 65537 /dev/urandom > "file_65537"
cp "file_65537" ".original_65537"

echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "file_65537" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Encrypt file of size 65537"
else
    pass_test "Succeeds: Encrypt file of size 65537"
fi

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "file_65537.enc" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Decrypt file of size 65537"
else
    pass_test "Succeeds: Decrypt file of size 65537"
fi

cmp -s "file_65537" ".original_65537"
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Match decrypted file of size 65537"
else
    pass_test "Succeeds: Match decrypted file of size 65537"
fi

# Test 1 MB file
head -c 1048576 /dev/urandom > "file_1048576"
cp "file_1048576" ".original_1048576"

echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "file_1048576" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Encrypt file of size 1048576"
else
    pass_test "Succeeds: Encrypt file of size 1048576"
fi

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "file_1048576.enc" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Decrypt file of size 1048576"
else
    pass_test "Succeeds: Decrypt file of size 1048576"
fi

cmp -s "file_1048576" ".original_1048576"
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Match decrypted file of size 1048576"
else
    pass_test "Succeeds: Match decrypted file of size 1048576"
fi

# Set up a victim file for tampering and deletion tests
echo "This is confidential data for tampering tests" > "victim.txt"
cp "victim.txt" ".original_victim"

echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "victim.txt" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Encrypt victim file"
else
    pass_test "Succeeds: Encrypt victim file"
fi

if [ -f "victim.txt" ]; then
    fail_test "Succeeds: Remove plaintext victim file after encryption"
else
    pass_test "Succeeds: Remove plaintext victim file after encryption"
fi

if [ ! -f "victim.txt.enc" ]; then
    fail_test "Succeeds: Create encrypted victim file"
else
    pass_test "Succeeds: Create encrypted victim file"
fi

grep -q -F "confidential data" "victim.txt.enc"
if [ $? -eq 0 ]; then
    fail_test "Succeeds: Ensure ciphertext differs from plaintext"
else
    pass_test "Succeeds: Ensure ciphertext differs from plaintext"
fi

# Tampering test
cp "victim.txt.enc" "pristine_victim.txt.enc"
cp "pristine_victim.txt.enc" "tampered_victim.txt.enc"
printf '\xff' | dd of="tampered_victim.txt.enc" bs=1 seek=60 conv=notrunc 2>/dev/null

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "tampered_victim.txt.enc" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    fail_test "Fails: Decrypt a tampered ciphertext"
else
    pass_test "Fails: Decrypt a tampered ciphertext"
fi

if [ -f "tampered_victim.txt" ]; then
    fail_test "Succeeds: Prevent tampered file creation"
else
    pass_test "Succeeds: Prevent tampered file creation"
fi

# Truncation test
cp "pristine_victim.txt.enc" "truncated_victim.txt.enc"
truncate -s -5 "truncated_victim.txt.enc"

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "truncated_victim.txt.enc" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    fail_test "Fails: Decrypt a truncated ciphertext"
else
    pass_test "Fails: Decrypt a truncated ciphertext"
fi

if [ -f "truncated_victim.txt" ]; then
    fail_test "Succeeds: Prevent truncated file creation"
else
    pass_test "Succeeds: Prevent truncated file creation"
fi

# Secure deletion (shred) test
key_directory=".secure_files/${USER_NAME}.keys"
key_count_before_shred=$(find "${key_directory}" -type f | wc -l)
cp "pristine_victim.txt.enc" "backup_victim.txt.enc"

echo "TestPass1234" | "$BINARY_PATH" shred --user "$USER_NAME" "pristine_victim.txt.enc" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Execute shred command"
else
    pass_test "Succeeds: Execute shred command"
fi

if [ -f "pristine_victim.txt.enc" ]; then
    fail_test "Succeeds: Remove encrypted file after shredding"
else
    pass_test "Succeeds: Remove encrypted file after shredding"
fi

key_count_after_shred=$(find "${key_directory}" -type f | wc -l)
expected_key_count=$((key_count_before_shred - 1))

if [ "$key_count_after_shred" -ne "$expected_key_count" ]; then
    fail_test "Succeeds: Remove exactly one key file during shred"
else
    pass_test "Succeeds: Remove exactly one key file during shred"
fi

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "backup_victim.txt.enc" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    fail_test "Fails: Decrypt a file with a shredded key"
else
    pass_test "Fails: Decrypt a file with a shredded key"
fi

# Set up a target for failure tests
echo "target file" > "target.txt"
cp "target.txt" "backup_target.txt"
echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "target.txt" >/dev/null 2>&1

# Authentication failures (target.txt must not exist yet, or decrypt stops before it reads the password)
other_user="nobody"
if [ "$USER_NAME" = "nobody" ]; then
    other_user="root"
fi

assert_failure_with_password "Fails: Decrypt with wrong password" "WrongPass1234" decrypt --user "$USER_NAME" "target.txt.enc"

assert_failure_with_password "Fails: Decrypt with empty password" "" decrypt --user "$USER_NAME" "target.txt.enc"

wrong_password_count=$(grep -c "reason=\"wrong password or corrupted profile\"" "secure_files.log")
if [ "$wrong_password_count" -ne 2 ]; then
    fail_test "Succeeds: Reject both bad passwords at the password check"
else
    pass_test "Succeeds: Reject both bad passwords at the password check"
fi

assert_failure_with_password "Fails: Decrypt as wrong user" "TestPass1234" decrypt --user "$other_user" "target.txt.enc"

assert_failure_with_password "Fails: Initialise existing profile" "TestPass1234\nTestPass1234" init --user "$USER_NAME"

cp "backup_target.txt" "target.txt"

# Argument parsing failures
assert_failure_no_password "Fails: Run with no arguments"

assert_failure_with_password "Fails: Run unknown command" "TestPass1234" boguscmd --user "$USER_NAME" "target.txt"

assert_failure_with_password "Fails: Encrypt without user flag" "TestPass1234" encrypt "target.txt"

assert_failure_with_password "Fails: Encrypt with double user flag" "TestPass1234" encrypt --user "$USER_NAME" --user "$USER_NAME" "target.txt"

assert_failure_with_password "Fails: Encrypt with two file paths" "TestPass1234" encrypt --user "$USER_NAME" "target.txt" "other.txt"

assert_failure_with_password "Fails: Initialise with a file path" "TestPass1234" init --user "$USER_NAME" "target.txt"

# Invalid names
assert_failure_with_password "Fails: Encrypt with semicolon in username" "TestPass1234" encrypt --user "bob;id" "target.txt"

assert_failure_with_password "Fails: Encrypt with 33 character username" "TestPass1234" encrypt --user "a12345678901234567890123456789012" "target.txt"

# Path validation failures
assert_failure_with_password "Fails: Encrypt using parent traversal" "TestPass1234" encrypt --user "$USER_NAME" "../target.txt"

assert_failure_with_password "Fails: Encrypt using absolute path" "TestPass1234" encrypt --user "$USER_NAME" "/etc/hostname"

assert_failure_with_password "Fails: Encrypt with empty path string" "TestPass1234" encrypt --user "$USER_NAME" ""

assert_failure_with_password "Fails: Encrypt missing file" "TestPass1234" encrypt --user "$USER_NAME" "does_not_exist.txt"

mkdir -p "directory_target"
assert_failure_with_password "Fails: Encrypt a directory" "TestPass1234" encrypt --user "$USER_NAME" "directory_target"

ln -s "target.txt" "symlink_target.txt"
assert_failure_with_password "Fails: Encrypt a symbolic link" "TestPass1234" encrypt --user "$USER_NAME" "symlink_target.txt"

long_filename=$(printf "%01100d" 1)
assert_failure_with_password "Fails: Encrypt a file with a path exceeding limits" "TestPass1234" encrypt --user "$USER_NAME" "$long_filename"

assert_failure_with_password "Fails: Decrypt a plaintext file without .enc suffix" "TestPass1234" decrypt --user "$USER_NAME" "target.txt"

# The tool's own files must never be encrypted, because encrypt overwrites and removes the original
profile_path=".secure_files/${USER_NAME}.profile"
cp "$profile_path" ".original_profile"
first_key_file=$(find "${key_directory}" -type f -name '*.key' | head -n 1)

assert_failure_with_password "Fails: Encrypt the profile" "TestPass1234" encrypt --user "$USER_NAME" "$profile_path"

assert_failure_with_password "Fails: Encrypt a key file" "TestPass1234" encrypt --user "$USER_NAME" "$first_key_file"

assert_failure_with_password "Fails: Encrypt the log file" "TestPass1234" encrypt --user "$USER_NAME" "secure_files.log"

ln -s . "working_dir_alias"
assert_failure_with_password "Fails: Encrypt the profile through a symlinked folder" "TestPass1234" encrypt --user "$USER_NAME" "working_dir_alias/${profile_path}"

ln "$profile_path" "profile_hard_link"
assert_failure_with_password "Fails: Encrypt a hard link to the profile" "TestPass1234" encrypt --user "$USER_NAME" "profile_hard_link"
rm "profile_hard_link"

cmp -s "$profile_path" ".original_profile"
if [ $? -ne 0 ] || [ ! -f "$first_key_file" ] || [ ! -f "secure_files.log" ]; then
    fail_test "Succeeds: Keep the profile, key file and log intact"
else
    pass_test "Succeeds: Keep the profile, key file and log intact"
fi

# the helpers always run BINARY_PATH, so the copy that encrypts itself is run directly
cp "$BINARY_PATH" "program_copy"
echo "TestPass1234" | ./program_copy encrypt --user "$USER_NAME" "program_copy" >/dev/null 2>&1
program_exit_code=$?

if [ $program_exit_code -eq 0 ] || [ -f "program_copy.enc" ] || ! cmp -s "program_copy" "$BINARY_PATH"; then
    fail_test "Fails: Encrypt the running program"
else
    pass_test "Fails: Encrypt the running program"
fi
rm -f "program_copy"

# Locked memory: root can lock memory past the limit, so this only proves something for a normal user
if [ "$(id -u)" -ne 0 ] && command -v prlimit >/dev/null 2>&1; then
    echo "lock test" > "lock_target.txt"
    raw_output=$(echo "TestPass1234" | prlimit --memlock=0:0 "$BINARY_PATH" encrypt --user "$USER_NAME" "lock_target.txt" 2>&1)
    lock_exit_code=$?

    if [ $lock_exit_code -eq 0 ] || [ ! -f "lock_target.txt" ] || [ -f "lock_target.txt.enc" ]; then
        fail_test "Fails: Encrypt when memory cannot be locked"
    else
        pass_test "Fails: Encrypt when memory cannot be locked"
    fi
fi

# Ownership and permission failures
# runs only where sudo works without a password prompt, otherwise the file would not exist and the test would prove nothing
if [ "$(id -u)" -ne 0 ] && sudo -n touch "root_owned.txt" 2>/dev/null; then
    assert_failure_with_password "Fails: Encrypt a file owned by root" "TestPass1234" encrypt --user "$USER_NAME" "root_owned.txt"
    sudo -n rm "root_owned.txt"
fi

echo "read only target" > "readonly.txt"
chmod 400 "readonly.txt"
original_inode=$(stat -c %i "readonly.txt")
assert_failure_with_password "Fails: Encrypt a read-only file" "TestPass1234" encrypt --user "$USER_NAME" "readonly.txt"

if [ -f "readonly.txt.enc" ]; then
    fail_test "Succeeds: Prevent read only target deletion"
else
    pass_test "Succeeds: Prevent read only target deletion"
fi

new_inode=$(stat -c %i "readonly.txt" 2>/dev/null || echo "missing")
if [ "$original_inode" != "$new_inode" ]; then
    fail_test "Succeeds: Retain original read only file untouched"
else
    pass_test "Succeeds: Retain original read only file untouched"
fi

# Symlink directory escape
outside_directory=$(mktemp -d)
ln -s "$outside_directory" "symlinked_dir"
echo "target" > "${outside_directory}/escape_target.txt"

assert_failure_with_password "Fails: Encrypt a file inside a symlinked directory" "TestPass1234" encrypt --user "$USER_NAME" "symlinked_dir/escape_target.txt"

rm -r -- "$outside_directory"

# Control characters
control_char_name=$(printf "a\x1bb")
echo "target" > "$control_char_name"

assert_failure_with_password "Fails: Encrypt a file with an ESC control character" "TestPass1234" encrypt --user "$USER_NAME" "$control_char_name"

# Valid sub-directory encryption
mkdir -p "valid_sub"
echo "target" > "valid_sub/deep_target.txt"

echo "TestPass1234" | "$BINARY_PATH" encrypt --user "$USER_NAME" "valid_sub/deep_target.txt" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Encrypt file in a valid subdirectory"
else
    pass_test "Succeeds: Encrypt file in a valid subdirectory"
fi

echo "TestPass1234" | "$BINARY_PATH" decrypt --user "$USER_NAME" "valid_sub/deep_target.txt.enc" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    fail_test "Succeeds: Decrypt file in a valid subdirectory"
else
    pass_test "Succeeds: Decrypt file in a valid subdirectory"
fi

# Log file verification
log_permissions=$(stat -c %a "secure_files.log")
if [ "$log_permissions" != "600" ]; then
    fail_test "Succeeds: Enforce 0600 log file permissions"
else
    pass_test "Succeeds: Enforce 0600 log file permissions"
fi

completed_operations=$(grep "outcome=success reason=\"completed\"" "secure_files.log" | wc -l)
if [ "$completed_operations" -lt 1 ]; then
    fail_test "Succeeds: Log successful completion events"
else
    pass_test "Succeeds: Log successful completion events"
fi

if grep -F -e "TestPass1234" -e "WrongPass1234" -e "12345678901" -e "TestPass1235" "secure_files.log"; then
    fail_test "Succeeds: Keep passwords out of the log file"
else
    pass_test "Succeeds: Keep passwords out of the log file"
fi

# Final results
if [ $failure_count -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "COMPLETED WITH ${failure_count} FAILURES"
    exit 1
fi
