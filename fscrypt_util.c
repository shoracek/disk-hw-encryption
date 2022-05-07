#include <linux/fscrypt.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

int get_key_status(int fd, const unsigned char *identifier)
{
    int err = 0;

    struct fscrypt_get_key_status_arg request = { 0 };
    memcpy(request.key_spec.u.identifier, identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);
    request.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;

    err = ioctl(fd, FS_IOC_GET_ENCRYPTION_KEY_STATUS, &request);
    if (err != 0)
        printf("err '%s' on %i\n", strerror(errno), __LINE__);

    printf("status: %s, user count: %i\n",
           request.status == FSCRYPT_KEY_STATUS_ABSENT               ? "ABSENT" :
           request.status == FSCRYPT_KEY_STATUS_PRESENT              ? "PRESENT" :
           request.status == FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED ? "INCOMPLETELY REMOVED" :
                                                                       "INVALID VALUE",
           request.user_count);

    return err;
}

int get_policy_and_status(int fd)
{
    int err = 0;
    struct fscrypt_get_policy_ex_arg request2 = { 0 };
    request2.policy_size = sizeof(request2.policy);
    err = ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, &request2);
    if (err != 0)
        printf("err '%s' on %i\n", strerror(errno), __LINE__);

    if (request2.policy.version == FSCRYPT_POLICY_V2) {
        struct fscrypt_policy_v2 *policy = &request2.policy.v2;
        printf("contents_encryption_mode: %s, filenames_encryption_mode %s\nPAD_4: %i, PAD_8: %i, PAD_16: %i, PAD_32: %i\nDIRECT_KEY: %i, IV_INO_LBLK_32: %i, IV_INO_LBLK_64: %i\n",
               policy->contents_encryption_mode == FSCRYPT_MODE_AES_256_CTS ? "AES_256_CTS" :
               policy->contents_encryption_mode == FSCRYPT_MODE_AES_256_XTS ? "AES_256_XTS" :
                                                                              "SOMETHING ELSE",
               policy->filenames_encryption_mode == FSCRYPT_MODE_AES_256_CTS ? "AES_256_CTS" :
               policy->filenames_encryption_mode == FSCRYPT_MODE_AES_256_XTS ? "AES_256_XTS" :
                                                                               "SOMETHING ELSE",
               !!(policy->flags & FSCRYPT_POLICY_FLAGS_PAD_4), !!(policy->flags & FSCRYPT_POLICY_FLAGS_PAD_8),
               !!(policy->flags & FSCRYPT_POLICY_FLAGS_PAD_16), !!(policy->flags & FSCRYPT_POLICY_FLAGS_PAD_32),
               !!(policy->flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY),
               !!(policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32),
               !!(policy->flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64));
        for (int i = 0; i < FSCRYPT_KEY_IDENTIFIER_SIZE; ++i) {
            printf("%02x", policy->master_key_identifier[i]);
        }
    }
    printf("\n");

    // get key status 2
    struct fscrypt_get_key_status_arg request3 = { 0 };
    memcpy(request3.key_spec.u.identifier, request2.policy.v2.master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);

    request3.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;

    err = ioctl(fd, FS_IOC_GET_ENCRYPTION_KEY_STATUS, &request3);
    if (err != 0)
        printf("err '%s' on %i\n", strerror(errno), __LINE__);

    printf("status: %s, user count: %i\n",
           request3.status == FSCRYPT_KEY_STATUS_ABSENT               ? "ABSENT" :
           request3.status == FSCRYPT_KEY_STATUS_PRESENT              ? "PRESENT" :
           request3.status == FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED ? "INCOMPLETELY REMOVED" :
                                                                        "INVALID VALUE",
           request3.user_count);

    return err;
}

void handle_error(const char *source)
{
    printf("%s: %s\n", source, strerror(errno));
    exit(1);
}

int add_key(int fd, unsigned char *key, ssize_t key_len, unsigned char *identifier)
{
    int err = 0;

    struct fscrypt_add_key_arg *key_request = calloc(1, sizeof(struct fscrypt_add_key_arg) + key_len);
    if (key_request == NULL)
        handle_error("add_key::calloc");

    key_request->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    key_request->key_id = 0;
    key_request->raw_size = key_len;
    memcpy(key_request->raw, key, key_len);
    /*
    err = getrandom(key_request->raw, key_len, 0);
    if (err != key_len)
        handle_error("getrandom");
    */

    err = ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, key_request);
    if (err != 0)
        handle_error("FS_IOC_ADD_ENCRYPTION_KEY");

    memcpy(identifier, key_request->key_spec.u.identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);

    free(key_request);

    return err;
}

int remove_key(int fd, unsigned char *identifier)
{
    int err = 0;

    struct fscrypt_remove_key_arg request = { 0 };
    memcpy(request.key_spec.u.identifier, identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);
    request.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;

    err = ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY, &request);
    if (err != 0)
        printf("err '%s' on %i\n", strerror(errno), __LINE__);

    return err;
}

int set_policy(int fd, unsigned char *identifier)
{
    int err = 0;

    struct fscrypt_policy_v2 policy_request = { 0 };
    policy_request.version = 2;
    policy_request.contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS;
    policy_request.filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS;
    policy_request.flags = FSCRYPT_POLICY_FLAGS_PAD_8 | FSCRYPT_POLICY_FLAGS_PAD_16 | FSCRYPT_POLICY_FLAGS_PAD_32;
    memcpy(policy_request.master_key_identifier, identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);

    err = ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy_request);
    if (err != 0)
        printf("err '%s' on %i\n", strerror(errno), __LINE__);

    return err;
}

void str_to_bytes(const char *src, unsigned char *dst, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        sscanf(src + i * 2, "%2hhx", dst + i);
    }
}

void print_usage()
{
    printf("add/remove/set/get folder identifier\n");
    exit(1);
}

int main(int argc, char **argv)
{
    unsigned char identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
    unsigned char key[128];
    int fd;

    if (argc != 4) {
        print_usage();
    }

    fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        handle_error("open");

    if (strcmp(argv[1], "add") == 0) {
        str_to_bytes(argv[3], key, strlen(argv[3]) / 2);
        add_key(fd, key, 64, identifier);

        for (int i = 0; i < FSCRYPT_KEY_IDENTIFIER_SIZE; ++i)
            printf("%02x", identifier[i]);
        printf("\n");
    } else if (strcmp(argv[1], "remove") == 0) {
        str_to_bytes(argv[3], identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);

        remove_key(fd, identifier);
    } else if (strcmp(argv[1], "set") == 0) {
        str_to_bytes(argv[3], identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);

        set_policy(fd, identifier);
    } else if (strcmp(argv[1], "get") == 0) {
        get_policy_and_status(fd);
    } else {
        print_usage();
    }

    close(fd);
}