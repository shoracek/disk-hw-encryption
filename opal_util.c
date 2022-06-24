#include <linux/nvme_ioctl.h>
#include <linux/fscrypt.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <scsi/sg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <argp.h>

uint16_t base_comID = 0;

/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0) {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

int hex_add(unsigned char *a, size_t a_len, size_t b)
{
    size_t i = 0;
    int extra = 0;
    while ((b > 0 || extra > 0) && i < a_len) {
        int next_extra = (a[a_len - i - 1] + (b % 256) + extra) > 255;

        a[a_len - i - 1] += (b % 256) + extra;

        b /= 256;
        i += 1;
        extra = next_extra;
    }

    return b > 0;
}

#define ATA_TRUSTED_RECEIVE 0x5c
#define ATA_TRUSTED_SEND 0x5e
#define TCG_LEVEL_0_DISCOVERY_PROTOCOL_ID 0x01
#define TCG_LEVEL_0_DISCOVERY_COMID 0x0001

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_Storage_Architecture_Core_Spec_v2.01_r1.00.pdf
// Table 242 MethodID UIDs
#define METHOD_UID_START_SESSION "\x00\x00\x00\x00\x00\x00\xff\x02"
#define METHOD_UID_GET "\x00\x00\x00\x06\x00\x00\x00\x16"
#define METHOD_UID_SET "\x00\x00\x00\x06\x00\x00\x00\x17"

#define SMUID "\x00\x00\x00\x00\x00\x00\x00\xff"
#define LOCKING_SP_UID "\x00\x00\x02\x05\x00\x00\x00\x02"
#define ADMIN1_UID "\x00\x00\x00\x09\x00\x01\x00\x01"

// https://trustedcomputinggroup.org/wp-content/uploads/TCG-Storage-Opal-SSC-v2p02-r1p0_pub24jan2022.pdf
// Table 39 Locking SP
#define LOCKING_RANGE_NNNN_UID "\x00\x00\x08\x02\x00\x03\x00\x00"
#define LOCKING_TABLE_ACTIVE_KEY 0xa

// Table 166 Status Codes
enum MethodStatusCode {
    MSC_SUCCESS = 0x00,
    MSC_NOT_AUTHORIZED = 0x01,
    // MSC_OBSOLETE = 0x02,
    MSC_SP_BUSY = 0x03,
    MSC_SP_FAILED = 0x04,
    MSC_SP_DISABLED = 0x05,
    MSC_SP_FROZEN = 0x06,
    MSC_NO_SESSIONS_AVAILABLE = 0x07,
    MSC_UNIQUENESS_CONFLICT = 0x08,
    MSC_INSUFFICIENT_SPACE = 0x09,
    MSC_INSUFFICIENT_ROWS = 0x0A,
    MSC_INVALID_PARAMETER = 0x0C,
    // MSC_OBSOLETE = 0x0D,
    // MSC_OBSOLETE = 0x0E,
    MSC_TPER_MALFUNCTION = 0x0F,
    MSC_TRANSACTION_FAILURE = 0x10,
    MSC_RESPONSE_OVERFLOW = 0x11,
    MSC_AUTHORITY_LOCKED_OUT = 0x12,
    MSC_FAIL = 0x3F,
};

const char *MSC_to_string(enum MethodStatusCode msc)
{
    switch (msc) {
    case MSC_SUCCESS:
        return "MSC_SUCCESS";
    case MSC_NOT_AUTHORIZED:
        return "MSC_NOT_AUTHORIZED";
    case MSC_SP_BUSY:
        return "MSC_SP_BUSY";
    case MSC_SP_FAILED:
        return "MSC_SP_FAILED";
    case MSC_SP_DISABLED:
        return "MSC_SP_DISABLED";
    case MSC_SP_FROZEN:
        return "MSC_SP_FROZEN";
    case MSC_NO_SESSIONS_AVAILABLE:
        return "MSC_NO_SESSIONS_AVAILABLE";
    case MSC_UNIQUENESS_CONFLICT:
        return "MSC_UNIQUENESS_CONFLICT";
    case MSC_INSUFFICIENT_SPACE:
        return "MSC_INSUFFICIENT_SPACE";
    case MSC_INSUFFICIENT_ROWS:
        return "MSC_INSUFFICIENT_ROWS";
    case MSC_INVALID_PARAMETER:
        return "MSC_INVALID_PARAMETER";
    case MSC_TPER_MALFUNCTION:
        return "MSC_TPER_MALFUNCTION";
    case MSC_TRANSACTION_FAILURE:
        return "MSC_TRANSACTION_FAILURE";
    case MSC_RESPONSE_OVERFLOW:
        return "MSC_RESPONSE_OVERFLOW";
    case MSC_AUTHORITY_LOCKED_OUT:
        return "MSC_AUTHORITY_LOCKED_OUT";
    case MSC_FAIL:
        return "MSC_FAIL";
    default:
        return "YIKES";
    }
}

struct identify_controller_data {
    char vid[2];
    char ssvid[2];
    char sn[20];
    char model_number[40];
    char firmware_revision[8];
    char _filler[184];
};

struct Level0DiscoveryHeader {
    uint32_t length;
    uint32_t revision;
    char reserved[8];
    char vendor_specific[32];
};

struct Level0DiscoverySharedFeature {
    uint16_t feature_code;
    uint8_t reserved;
    uint8_t length;
};

/*
    An Opal SSC compliant SD SHALL return the following:
    • Feature Code = 0x0001
    • Version = 0x1 or any version that supports the defined features in this SSC
    • Length = 0x0C
    • ComID Mgmt Supported = VU
    • Streaming Supported = 1
    • Buffer Mgmt Supported = VU
    • ACK/NACK Supported = VU
    • Async Supported = VU
    • Sync Supported = 1
*/
struct Level0DiscoveryTPerFeature {
    struct Level0DiscoverySharedFeature shared;
    uint8_t sync_supported : 1;
    uint8_t async_supported : 1;
    uint8_t ack_nack_supported : 1;
    uint8_t buffer_mgmt_supported : 1;
    uint8_t streaming_supported : 1;
    uint8_t reserved_2 : 1;
    uint8_t comID_mgmt_supported : 1;
    uint8_t reserved_3 : 1;
    uint8_t reserved_4[11];
};

struct Level0DiscoveryGeometryFeature {
    struct Level0DiscoverySharedFeature shared;
    uint8_t reserved_2;
    uint8_t reserved_3[7];
    uint32_t logical_block_size;
    uint64_t alignment_granularity;
    uint64_t lowest_alignment_LBA;
};

/*
    • Feature Code = 0x0002
    • Version = 0x1 or any version that supports the defined features in this SSC
    • Length = 0x0C
    • MBR Done = **
    • MBR Enabled = **
    • Media Encryption = 1
    • Locked = **
    • Locking Enabled = See 3.1.1.3.1
    • Locking Supported = 1
*/
struct Level0DiscoveryLockingFeature {
    struct Level0DiscoverySharedFeature shared;
    uint8_t locking_supported : 1;
    uint8_t locking_enabled : 1;
    uint8_t locked : 1;
    uint8_t media_encryption : 1;
    uint8_t MBR_enabled : 1;
    uint8_t MBR_done : 1;
    uint8_t reserved_2 : 2;
    uint8_t reserved_3[11];
};

/*
    An Opal SSC compliant Storage Device SHALL return the following:
    • Feature Code = 0x0203
    • Feature Descriptor Version Number = 0x2 or any version that supports the defined features in this SSC
    • SSC Minor Version Number = As specified in Table 8
    • Length = 0x10
    • Base ComID = VU
    • Number of ComIDs = 0x0001 or larger
    • Range Crossing Behavior = VU
    o 0 = The Storage Device supports commands addressing consecutive LBAs in more than one LBA
    range if all the LBA ranges addressed are unlocked. See section 4.3.7.
    o 1 = The Storage Device terminates commands addressing consecutive LBAs in more than one LBA
    range. See 4.3.7
    • Number of Locking SP Admin Authorities = 4 or larger
    • Number of Locking SP User Authorities = 8 or larger
    • Initial C_PIN_SID PIN Indicator = VU
*/

#pragma pack(1)
struct Level0DiscoveryOpal2Feature {
    struct Level0DiscoverySharedFeature shared;
    uint16_t base_comID;
    uint16_t number_of_comIDs;
    uint8_t range_crossing_behaviour : 1;
    uint8_t reserved_1 : 7;
    uint16_t number_of_locking_admin_authorities_supported;
    uint16_t number_of_locking_user_authorities_supported;
    uint8_t initial_pin_indicator;
    uint8_t behavior_of_pin_upon_revert;
    uint8_t reserved_2[5];
};

uint64_t swap_endian_64(uint64_t x)
{
    return ((x & 0x00000000000000ff) << 56) | ((x & 0x000000000000ff00) << 40) | ((x & 0x0000000000ff0000) << 24) |
           ((x & 0x00000000ff000000) << 8) | ((x & 0x000000ff00000000) >> 8) | ((x & 0x0000ff0000000000) >> 24) |
           ((x & 0x00ff000000000000) >> 40) | ((x & 0xff00000000000000) >> 56);
}

uint32_t swap_endian_32(uint32_t x)
{
    return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24);
}

uint16_t swap_endian_16(uint16_t x)
{
    return ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
}

int nvme_identify(int fd)
{
    int err = 0;
    struct identify_controller_data response = { 0 };
    struct nvme_admin_cmd cmd = { 0 };

    // https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0b-2021.12.18-Ratified.pdf
    // Figure 138
    cmd.opcode = 0x06;
    // 5.17, Figure 273
    cmd.cdw10 = 1;
    cmd.data_len = 239; // for some reason, 240 and more writes way too many bytes
    cmd.addr = (unsigned long long)&response;

    err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (err != 0)
        printf("ioctl: %s\n", strerror(errno));

    printf("model_number: '%.*s'\nsn: '%.*s'\nfirmware_revision: '%.*s'\n", sizeof(response.model_number),
           response.model_number, sizeof(response.sn), response.sn, sizeof(response.firmware_revision),
           response.firmware_revision);

    return err;
}

void tcg_discovery_0_process_feature(void *data, int feature_code, int print)
{
    if (feature_code == 0x0001) {
        struct Level0DiscoveryTPerFeature *body = data;
        if (print)
            printf("TPer feature:\n"
                   " - comID mgmt supported %i\n"
                   " - streaming supported %i\n"
                   " - buffer mgmt supported %i\n"
                   " - ack nack supported %i\n"
                   " - async supported %i\n"
                   " - sync supported %i\n",
                   body->comID_mgmt_supported, body->streaming_supported, body->buffer_mgmt_supported,
                   body->ack_nack_supported, body->async_supported, body->sync_supported);
    } else if (feature_code == 0x0002) {
        struct Level0DiscoveryLockingFeature *feature = data;
        if (print)
            printf("Locking feature:\n"
                   " - locking supported: %i\n"
                   " - locking enabled %i\n"
                   " - locked %i\n"
                   " - media encryption: %i\n"
                   " - MBR enabled %i\n"
                   " - MBR done %i\n",
                   feature->locking_supported, feature->locking_enabled, feature->locked, feature->media_encryption,
                   feature->MBR_enabled, feature->MBR_done);
    } else if (feature_code == 0x0003) {
        struct Level0DiscoveryGeometryFeature *feature = data;
        if (print)
            printf("Geometry feature:\n"
                   " - logical block size: %i\n"
                   " - alignment granularity: %li\n"
                   " - lowest alignment LBA: %li\n",
                   swap_endian_32(feature->logical_block_size), swap_endian_64(feature->alignment_granularity),
                   swap_endian_64(feature->lowest_alignment_LBA));
    } else if (feature_code == 0x0203) {
        struct Level0DiscoveryOpal2Feature *body = data;
        if (print)
            printf("Opal SSC V2.00 Feature:\n"
                   " - base comID %i\n"
                   " - number of comIDs %i\n"
                   " - number of locking SP admin authorities %i\n"
                   " - number of locking SP user authorities %i\n",
                   swap_endian_16(body->base_comID), swap_endian_16(body->number_of_comIDs),
                   swap_endian_16(body->number_of_locking_admin_authorities_supported),
                   swap_endian_16(body->number_of_locking_user_authorities_supported));

        base_comID = swap_endian_16(body->base_comID);
    } else {
        if (print)
            printf("unimplemented feature %i\n", feature_code);
    }
}

void tcg_discovery_0_process_response(void *data, int print)
{
    struct Level0DiscoveryHeader *header = data;
    uint32_t offset = sizeof(struct Level0DiscoveryHeader);
    uint32_t total_length = swap_endian_32(header->length);

    while (offset < total_length) {
        struct Level0DiscoverySharedFeature *body = data + offset;
        uint16_t feature_code = swap_endian_16(body->feature_code);

        tcg_discovery_0_process_feature(body, feature_code, print);

        offset += body->length + sizeof(struct Level0DiscoverySharedFeature);
    }
}

int ata_trusted(int fd, uint8_t *response, size_t response_len, int cmd, int protocol, int comID)
{
    // send_packet(response, response_len);

    // https://wiki.osdev.org/ATA_Command_Matrix
    // https://en.wikipedia.org/wiki/SCSI_command#List_of_SCSI_commands
    // -> ATA PASS-THROUGH(12) -> ATA Command Pass-Through
    // https://www.t10.org/ftp/t10/document.04/04-262r8.pdf
    struct CDB_ATA_PASS_THROUGH {
        uint8_t operation_code; // = 0xa1
        uint8_t reserved_1 : 1;
        uint8_t protocol : 4;
        uint8_t multiple_count : 3;
        uint8_t t_length : 2;
        uint8_t byt_blok : 1;
        uint8_t t_dir : 1;
        uint8_t reserved_2 : 1;
        uint8_t ck_cond : 1;
        uint8_t off_line : 1;
        union {
            struct {
                uint8_t features;
                uint8_t sector_count;
                uint8_t lba_low;
                uint8_t lba_mid;
                uint8_t lba_high;
                uint8_t device;
                uint8_t command;
            } original;
            // https://people.freebsd.org/~imp/asiabsdcon2015/works/d2161r5-ATAATAPI_Command_Set_-_3.pdf
            struct {
                uint8_t security_protocol;
                uint16_t transfer_length;
                uint16_t sp_specific;
                // uint8_t reserved_1 : 4; ??????? why are there extra 4 bits???????
                uint8_t reserved_2 : 4;
                uint8_t transport_dependent : 1;
                uint8_t obsolete_1 : 1;
                uint8_t na : 1;
                uint8_t obsolete_2 : 1;
                uint8_t command;
            } trusted_receive;
        };
        uint8_t reserved_3;
        uint8_t control;
    };

    if (response_len % 512 != 0) {
        response_len += 512 - (response_len % 512); // padding
    }

    struct CDB_ATA_PASS_THROUGH cdb = {
        .operation_code = 0xa1,
        // https://people.freebsd.org/~imp/asiabsdcon2015/works/d2161r5-ATAATAPI_Command_Set_-_3.pdf
        // Table 140 — TRUSTED RECEIVE command inputs
        // file:///home/shoracek/Downloads/d1532v2r4b-ATA-ATAPI-7-2.pdf
        .protocol = cmd == ATA_TRUSTED_RECEIVE ? 4 : 5, // PIO Data-In/Out
        .t_dir = cmd == ATA_TRUSTED_RECEIVE ? 1 : 0,
        .byt_blok = 1, // -> t_length contains number of blocks to transfer (bytes are waaaaay too slow)
        .t_length = 2, // -> transfer length in sector_count/trusted_receive.transfer_length
        .trusted_receive.security_protocol = protocol,
        .trusted_receive.transfer_length = response_len / 512,
        .trusted_receive.sp_specific = comID,
        .trusted_receive.command = cmd,
    };
    uint8_t sense[32] = { 0 };

    sg_io_hdr_t sg = {
        .interface_id = 'S',
        .dxfer_direction = cmd == ATA_TRUSTED_RECEIVE ? SG_DXFER_FROM_DEV : SG_DXFER_TO_DEV,
        .cmdp = (void *)&cdb,
        .cmd_len = sizeof(cdb),
        .dxferp = response,
        .dxfer_len = response_len,
        .timeout = 10000,

        .mx_sb_len = sizeof(sense),
        .sbp = sense,
    };

    if (ioctl(fd, SG_IO, &sg) < 0) {
        printf("bad ioctl %s\n", strerror(errno));
    }

    printf("%s:\n", cmd == ATA_TRUSTED_RECEIVE ? "received" : "sent");
    for (int x = 0; x < 254; ++x) {
        printf("%02x ", response[x]);
    }
    printf("\n");

    if (sense[0] != 0 || sense[1] != 0) {
        printf("got some sense:\n");
        // https://en.wikipedia.org/wiki/Key_Code_Qualifier ...
        for (int i = 0; i < sizeof(sense); ++i) {
            printf("%02x ", sense[i]);
        }
        printf("\n");
    }
}

int nvme_send(int fd, unsigned char *response, size_t response_len)
{
    int err = 0;
    // discovery 0

    struct nvme_admin_cmd cmd = { 0 };

    // structure of IF-RECV described in
    // https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0b-2021.12.18-Ratified.pdf
    // 5.25
    cmd.opcode = 0x82;
    // SPC-5 ... -> https://trustedcomputinggroup.org/wp-content/uploads/TCG_Storage_Architecture_Core_Spec_v2.01_r1.00.pdf
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_Storage_SIIS_v1p10_r1p29_pub_14nov2021.pdf
    // Table 22
    // protocol comID up comID lo reserved
    // 00000001 00000000 00000001 00000000
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG_Storage_Architecture_Core_Spec_v2.01_r1.00.pdf
    // 3.3.6 Level 0 Discovery

    cmd.cdw10 = 0x01000000 | 0x000100; // protocol 0x01, comid 0x0001
    cmd.cdw11 = response_len;
    cmd.data_len = response_len;
    cmd.addr = (unsigned long long)&response;

    err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (err != 0)
        printf("ioctl error %s 0x%02x\n", strerror(errno), err);

    return err;
}

#define TINY_ATOM_TOKEN(S, V) (uint8_t)(0b0 << 7 | S << 6 | V)
#define SHORT_ATOM_TOKEN_1(S, V) (uint8_t)(0b10 << 6 | S << 5 | V)
#define MEDIUM_ATOM_TOKEN_1(S, V) (uint8_t)(0b110 << 5 | S << 4 | V >> 8)
#define MEDIUM_ATOM_TOKEN_2(S, V) (uint8_t)(V)
#define START_LIST_TOKEN 0xf0
#define END_LIST_TOKEN 0xf1
#define START_NAME_TOKEN 0xf2
#define END_NAME_TOKEN 0xf3
#define CALL_TOKEN 0xf8
#define END_OF_DATA_TOKEN 0xf9
#define END_OF_SESSION_TOKEN 0xfa

#define PADDING_ALIGNMENT 512

void start_list(unsigned char *buffer, size_t *i)
{
    buffer[*i] = START_LIST_TOKEN;
    *i += 1;
}

void end_list(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_LIST_TOKEN;
    *i += 1;
}

void start_name(unsigned char *buffer, size_t *i)
{
    buffer[*i] = START_NAME_TOKEN;
    *i += 1;
}

void end_name_list(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_NAME_TOKEN;
    *i += 1;
}

void call_token(unsigned char *buffer, size_t *i)
{
    buffer[*i] = CALL_TOKEN;
    *i += 1;
}

void end_of_data(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_OF_DATA_TOKEN;
    *i += 1;
}

void end_session_token(unsigned char *buffer, size_t *i)
{
    buffer[*i] = END_OF_SESSION_TOKEN;
    *i += 1;
}

void method_status_list(unsigned char *buffer, size_t *i)
{
    buffer[*i] = START_LIST_TOKEN;
    *i += 1;
    for (int x = 0; x < 3; ++x) {
        buffer[*i] = 0x00;
        *i += 1;
    }
    buffer[*i] = END_LIST_TOKEN;
    *i += 1;
}

void tiny_atom(unsigned char *buffer, size_t *i, unsigned char S, unsigned char V)
{
    buffer[*i] = 0b0 << 7 | S << 6 | V;
    *i += 1;
}

void short_atom(unsigned char *buffer, size_t *i, unsigned char S, unsigned char *V, size_t V_len)
{
    buffer[*i] = 0b10 << 6 | S << 5 | V_len;
    *i += 1;

    memcpy(buffer + *i, V, V_len);
    *i += V_len;
}

void medium_atom(unsigned char *buffer, size_t *i, unsigned char S, unsigned char *V, size_t V_len)
{
    buffer[*i] = 0b110 << 5 | S << 4 | V_len >> 8;
    buffer[*i + 1] = 0b11111111 & V_len;
    *i += 2;

    memcpy(buffer + *i, V, V_len);
    *i += V_len;
}

uint64_t parse_int(const unsigned char *buffer, size_t *i)
{
    uint64_t result = 0;
    if ((buffer[*i] & (0b1 << 7)) == (0b0 << 7)) {
        // TODO
        result = buffer[*i] & 0b00111111;
        *i += 1;

        result = -1;
    } else if ((buffer[*i] & (0b11 << 6)) == (0b10 << 6)) {
        size_t len = buffer[*i] & (0b00011111);
        *i += 1;

        for (int j = 0; j < len; ++j) {
            result |= buffer[*i] << (((len - 1) - j) * 8);
            *i += 1;
        }
    }
    return result;
}

void table_get(unsigned char *buffer, size_t *i, unsigned char *invoking_uid, unsigned char start, unsigned char end)
{
    // Core: Table 226 Locking Table Description
    // Data Payload
    call_token(buffer, i);
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG-Storage-Opal-SSC-v2p02-r1p0_pub24jan2022.pdf
    // Table 39 Locking SP
    short_atom(buffer, i, 1, invoking_uid, 8);
    short_atom(buffer, i, 1, METHOD_UID_GET, 8);
    // [
    start_list(buffer, i);
    {
        start_list(buffer, i);
        {
            start_name(buffer, i);
            {
                // startColumn
                tiny_atom(buffer, i, 0, 3);
                tiny_atom(buffer, i, 0, start);
            }
            end_name_list(buffer, i);
            start_name(buffer, i);
            {
                // endColumn
                tiny_atom(buffer, i, 0, 4);
                tiny_atom(buffer, i, 0, end);
            }
            end_name_list(buffer, i);
        }
        end_list(buffer, i);
    }
    // ]
    end_list(buffer, i);
    end_of_data(buffer, i);
    method_status_list(buffer, i);
}

int locking_range_get(unsigned char *buffer, size_t *i, unsigned char locking_range_uid, unsigned char start,
                      unsigned char end)
{
    unsigned char locking_range_uid_str[] = LOCKING_RANGE_NNNN_UID;
    locking_range_uid_str[7] = locking_range_uid;
    table_get(buffer, i, locking_range_uid_str, start, end);
}

int locking_range_set(unsigned char *buffer, size_t *i, unsigned char locking_range_uid, uint16_t range_start,
                      uint16_t range_length, char read_lock_enabled, char write_lock_enabled, char read_locked,
                      char write_locked)
{
    // Core: Table 226 Locking Table Description
    // Data Payload
    call_token(buffer, i);
    unsigned char locking_range_uid_str[9] = LOCKING_RANGE_NNNN_UID;
    locking_range_uid_str[7] = locking_range_uid;
    short_atom(buffer, i, 1, locking_range_uid_str, 8);
    short_atom(buffer, i, 1, METHOD_UID_SET, 8);
    // [
    start_list(buffer, i);
    {
        // "Values" = [...]
        start_name(buffer, i);
        {
            tiny_atom(buffer, i, 0, 1);
            // [
            start_list(buffer, i);
            {
                if (range_start != UINT16_MAX) {
                    start_name(buffer, i);
                    {
                        printf("range_start = %i (actually 0)\n", range_start);
                        tiny_atom(buffer, i, 0, 3);
                        unsigned char tmp[] = "\x00\x00";
                        hex_add(tmp, 2, range_start);
                        short_atom(buffer, i, 0, tmp, 2);
                    }
                    end_name_list(buffer, i);
                }
                if (range_length != UINT16_MAX) {
                    start_name(buffer, i);
                    {
                        printf("range_length = %i (actually 512)\n", range_length);
                        tiny_atom(buffer, i, 0, 4);
                        unsigned char tmp[] = "\x00\x00";
                        hex_add(tmp, 2, range_length);
                        short_atom(buffer, i, 0, tmp, 2);
                    }
                    end_name_list(buffer, i);
                }
                if (read_lock_enabled != -1) {
                    start_name(buffer, i);
                    {
                        printf("read_lock_enabled = %i\n", read_lock_enabled);
                        tiny_atom(buffer, i, 0, 5);
                        tiny_atom(buffer, i, 0, read_lock_enabled);
                    }
                    end_name_list(buffer, i);
                }
                if (write_lock_enabled != -1) {
                    start_name(buffer, i);
                    {
                        printf("write_lock_enabled = %i\n", write_lock_enabled);
                        tiny_atom(buffer, i, 0, 6);
                        tiny_atom(buffer, i, 0, write_lock_enabled);
                    }
                    end_name_list(buffer, i);
                }
                if (read_locked != -1) {
                    start_name(buffer, i);
                    {
                        printf("read_locked = %i\n", read_locked);
                        tiny_atom(buffer, i, 0, 7);
                        tiny_atom(buffer, i, 0, read_locked);
                    }
                    end_name_list(buffer, i);
                }
                if (write_locked != -1) {
                    start_name(buffer, i);
                    {
                        printf("write_locked = %i\n", write_locked);
                        tiny_atom(buffer, i, 0, 8);
                        tiny_atom(buffer, i, 0, write_locked);
                    }
                    end_name_list(buffer, i);
                }
            }
            // ]
            end_list(buffer, i);
        }
        end_name_list(buffer, i);
    }
    // ]
    end_list(buffer, i);
    end_of_data(buffer, i);
    method_status_list(buffer, i);
}

int user_pin_set(unsigned char *buffer, size_t *i, unsigned char user_uid, unsigned char *user_pin, int user_pin_len)
{
    call_token(buffer, i);
    unsigned char user_uid_str[9] = "\x00\x00\x00\x0b\x00\x03\x00\x00";
    hex_add(user_uid_str, 8, user_uid);
    short_atom(buffer, i, 1, user_uid_str, 8);
    // Set Method UID
    short_atom(buffer, i, 1, METHOD_UID_SET, 8);
    // [
    start_list(buffer, i);
    {
        // "Values" = [...]
        start_name(buffer, i);
        {
            tiny_atom(buffer, i, 0, 1);
            // [
            start_list(buffer, i);
            {
                start_name(buffer, i);
                {
                    tiny_atom(buffer, i, 0, 3);
                    medium_atom(buffer, i, 1, user_pin, user_pin_len);
                }
                end_name_list(buffer, i);
            }
            // ]
            end_list(buffer, i);
        }
        end_name_list(buffer, i);
    }
    // ]
    end_list(buffer, i);
    end_of_data(buffer, i);
    method_status_list(buffer, i);
}

int user_enabled_set(unsigned char *buffer, size_t *i, unsigned char user_uid)
{
    call_token(buffer, i);
    char user_uid_str[9] = "\x00\x00\x00\x09\x00\x03\x00\x00"; // Locking SP Authority Table User1 UID
    user_uid_str[7] = user_uid;
    short_atom(buffer, i, 1, user_uid_str, 8);
    // Set Method UID
    short_atom(buffer, i, 1, METHOD_UID_SET, 8);
    // [
    start_list(buffer, i);
    {
        // "Values" = [...]
        start_name(buffer, i);
        {
            tiny_atom(buffer, i, 0, 1);
            // [
            start_list(buffer, i);
            {
                start_name(buffer, i);
                {
                    printf("enabled = 1\n");
                    tiny_atom(buffer, i, 0, 5);
                    tiny_atom(buffer, i, 0, 1);
                }
                end_name_list(buffer, i);
            }
            // ]
            end_list(buffer, i);
        }
        end_name_list(buffer, i);
    }
    // ]
    end_list(buffer, i);
    end_of_data(buffer, i);
    method_status_list(buffer, i);
}

int end_session(unsigned char *buffer, size_t *i)
{
    end_session_token(buffer, i);
}

int start_session(unsigned char *buffer, size_t *i, unsigned char *SPID, size_t SPID_len, unsigned char *host_challenge,
                  size_t host_challenge_len, unsigned char *host_exchange_authority, size_t host_exchange_authority_len,
                  unsigned char *host_signing_authority, size_t host_signing_authority_len)
{
    /*
        5.2.3.1 StartSession Method
        SMUID.StartSession [
        HostSessionID : uinteger,
        SPID : uidref {SPObjectUID},
        Write : boolean,
        HostChallenge = bytes,
        HostExchangeAuthority = uidref {AuthorityObjectUID},
        HostExchangeCert = bytes,
        HostSigningAuthority = uidref {AuthorityObjectUID},
        HostSigningCert = bytes,
        SessionTimeout = uinteger,
        TransTimeout = uinteger,
        InitialCredit = uinteger,
        SignedHash = bytes ]
        =>
        SMUID.SyncSession [ see SyncSession definition in 5.2.3.2]
    */

    // Data Payload
    call_token(buffer, i);
    // Session Manager UID
    short_atom(buffer, i, 1, SMUID, 8);
    // Method UID (Table 241) - StartSession
    short_atom(buffer, i, 1, METHOD_UID_START_SESSION, 8);
    // [
    start_list(buffer, i);
    {
        // HostSessionID : uinteger,
        // tiny_atom(buffer, i, 0, 1);
        buffer[*i] = 0x81;
        *i += 1;
        buffer[*i] = 0x69;
        *i += 1;

        // SPID : uidref {SPObjectUID},
        short_atom(buffer, i, 1, SPID, SPID_len);
        // Write : boolean,
        tiny_atom(buffer, i, 0, 1);
        // HostChallenge = bytes,
        if (host_challenge) {
            start_name(buffer, i);
            {
                tiny_atom(buffer, i, 0, 0);
                medium_atom(buffer, i, 1, host_challenge, host_challenge_len);
            }
            end_name_list(buffer, i);
        }
        // HostExchangeAuthority = uidref {AuthorityObjectUID},
        if (host_exchange_authority) {
            start_name(buffer, i);
            {
                tiny_atom(buffer, i, 0, 1);
                medium_atom(buffer, i, 1, host_exchange_authority, host_exchange_authority_len);
            }
            end_name_list(buffer, i);
        }
        // HostExchangeCert = bytes,
        // HostSigningAuthority = uidref {AuthorityObjectUID},
        if (host_signing_authority) {
            start_name(buffer, i);
            {
                tiny_atom(buffer, i, 0, 3);
                short_atom(buffer, i, 1, host_signing_authority, host_signing_authority_len);
            }
            end_name_list(buffer, i);
        }
        // HostSigningCert = bytes,
        // SessionTimeout = uinteger,
        // TransTimeout = uinteger,
        // InitialCredit = uinteger,
        // SignedHash = bytes
    }
    // ]
    end_list(buffer, i);
    end_of_data(buffer, i);
    method_status_list(buffer, i);
}

struct ComPacket {
    uint8_t reserved_1[4];
    uint16_t comid;
    uint16_t comid_extension;
    uint32_t outstanding_data;
    uint32_t min_transfer;
    uint32_t length;
};

struct Packet {
    uint64_t session;
    uint32_t seq_number;
    uint8_t reserved_1[2];
    uint16_t ack_type;
    uint32_t ack;
    uint32_t length;
};

struct DataSubPacket {
    uint8_t reserved_1[6];
    uint16_t kind;
    uint32_t length;
};

void ata_discovery(int fd, int print)
{
    uint8_t response[4096] = { 0 };
    ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, TCG_LEVEL_0_DISCOVERY_PROTOCOL_ID,
                TCG_LEVEL_0_DISCOVERY_COMID);
    tcg_discovery_0_process_response(response, print);
}

struct HeadersStruct {
    struct ComPacket com_packet;
    struct Packet packet;
    struct DataSubPacket data_subpacket;
};

void prepare_headers(unsigned char *buffer, size_t *i, uint64_t sp_session_id, uint64_t host_session_id)
{
    struct HeadersStruct *headers = (void *)(((unsigned char *)buffer));

    headers->com_packet.comid = swap_endian_16(base_comID);
    headers->packet.session = sp_session_id | host_session_id << 32;

    *i += sizeof(struct HeadersStruct);
}

void finish_headers(unsigned char *buffer, size_t *i)
{
    struct HeadersStruct *headers = (void *)(((unsigned char *)buffer));

    if ((*i % 4) != 0)
        *i += 4 - (*i % 4);

    headers->com_packet.length = swap_endian_32(*i - sizeof(struct ComPacket));
    headers->packet.length = swap_endian_32(swap_endian_32(headers->com_packet.length) - sizeof(struct Packet));
    headers->data_subpacket.length =
            swap_endian_32(swap_endian_32(headers->packet.length) - sizeof(struct DataSubPacket));

    if ((*i % 512) != 0)
        *i += PADDING_ALIGNMENT - (*i % PADDING_ALIGNMENT);
}

char *dev = "hello";
uint64_t HostSessionID = 0;
uint64_t SPSessionID = 0;

int init_session(int fd, unsigned char *SPID, unsigned char user_id, unsigned char *challenge, size_t challenge_len)
{
    // Taking ownership of the storage device
    size_t i = 0;
    struct ComPacket *com_packet;
    struct Packet *packet;
    struct DataSubPacket *data_subpacket;

    unsigned char buffer[4096] = { 0 };
    unsigned char response[4096] = { 0 };

    printf("Discovery 0:\n");
    ata_discovery(fd, 0);
    printf("    base ComID = %x\n", base_comID);

    // StartSession
    {
        printf("Sending StartSession (user_id=%i):\n", user_id);
        memset(buffer, 0, sizeof(buffer));
        i = 0;
        prepare_headers(buffer, &i, 0, 0); //  01 f2 00 d0 20

        unsigned char *salted_hashed_etc_challenge = challenge;
        if (user_id == 0) {
            unsigned char signing_auth[9] = ADMIN1_UID;
            start_session(buffer, &i, SPID, 8, salted_hashed_etc_challenge, challenge_len, NULL, 0, signing_auth, 8);
        } else {
            unsigned char signing_auth[9] = "\x00\x00\x00\x09\x00\x03\x00\x00";
            signing_auth[7] = user_id;
            start_session(buffer, &i, SPID, 8, salted_hashed_etc_challenge, challenge_len, NULL, 0, signing_auth, 8);
        }
        finish_headers(buffer, &i);
        ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

        printf("Getting SyncSession:\n");
        memset(response, 0, sizeof(response));
        ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);


        // SMUID.SyncSession [
        // HostSessionID : uinteger,
        // SPSessionID : uinteger,
        // SPChallenge = bytes,
        // SPExchangeCert = bytes,
        // SPSigningCert = bytes,
        // TransTimeout = uinteger,
        // InitialCredit = uinteger,
        // SignedHash = bytes ]
        i = 0;
        i += sizeof(struct HeadersStruct); // headers
        i += 1; // call token
        i += 1; // short atom
        i += 8; // invoking uid
        i += 1; // short atom
        i += 8; // method uid
        i += 1; // start list token
        HostSessionID = swap_endian_32(parse_int(response, &i));
        SPSessionID = swap_endian_32(parse_int(response, &i));
        printf("HostSessionID: %lx,  SPSessionID: %lx \n", HostSessionID, SPSessionID);
        i += 1; // end list token
        i += 1; // end of data token
        // method status list
        printf("method status code: %s (%i)\n", MSC_to_string(response[i + 1]), response[i + 1]);
        i += 5;
    }
    return 0;
}

void finish_session(int fd)
{
    size_t i = 0;
    struct ComPacket *com_packet;
    struct Packet *packet;
    struct DataSubPacket *data_subpacket;

    printf("Unlock range:\n");
    unsigned char buffer[4096] = { 0 };
    unsigned char response[4096] = { 0 };

    // end session
    {
        printf("Sending EndSession\n");
        memset(buffer, 0, sizeof(buffer));
        i = 0;
        prepare_headers(buffer, &i, SPSessionID, HostSessionID);
        end_session(buffer, &i);
        finish_headers(buffer, &i);

        ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

        printf("Getting EndSession Response:\n");
        memset(response, 0, sizeof(response));
        ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);
    }
}

void unlock_range(int fd, unsigned char locking_range_uid, unsigned char user_uid, char read_lock_enabled,
                  char write_lock_enabled, char read_locked, char write_locked, char *challenge, size_t challenge_len)
{
    int rc = 0;

    printf("Unlock range:\n");
    unsigned char buffer[4096] = { 0 };
    unsigned char response[4096] = { 0 };
    size_t i = 0;

    if (rc == 0) {
        init_session(fd, LOCKING_SP_UID, user_uid, challenge, challenge_len);
    }

    if (rc == 0) {
        printf("Sending Set LockingRange1:\n");
        memset(buffer, 0, sizeof(buffer));
        i = 0;
        prepare_headers(buffer, &i, SPSessionID, HostSessionID);
        locking_range_set(buffer, &i, locking_range_uid, -1, -1, read_lock_enabled, write_lock_enabled, read_locked,
                          write_locked);
        finish_headers(buffer, &i);
        ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

        printf("Getting Set LockingRange1 Result:\n");
        memset(response, 0, sizeof(response));
        ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);
        // -> []
        i = 0;
        i += sizeof(struct HeadersStruct);
        i += 1; // start list token
        i += 1; // end list token
        i += 1; // end of data token
        // method status list
        printf("method status code: %s (%i)\n", MSC_to_string(response[i + 1]), response[i + 1]);
        printf("\n");
    }

    if (rc == 0) {
        finish_session(fd);
    }
}

void setup_range(int fd, unsigned char locking_range_uid, unsigned char *challenge, size_t challenge_len, uint16_t start, uint16_t length)
{
    size_t i = 0;
    int rc = 0;

    printf("Unlock range:\n");
    unsigned char buffer[4096] = { 0 };
    unsigned char response[4096] = { 0 };

    if (rc == 0) {
        init_session(fd, LOCKING_SP_UID, 0, challenge, challenge_len);
    }

    if (rc == 0) {
        // Configures the range and enables read and write locking by changing RangeStart,
        // RangeLength, ReadLockEnabled and WriteLockEnabled for Locking_Range1
        printf("Sending Set LockingRange1:\n");
        memset(buffer, 0, sizeof(buffer));
        i = 0;
        prepare_headers(buffer, &i, SPSessionID, HostSessionID);
        locking_range_set(buffer, &i, 1, start, length, 1, 1, -1, -1);
        finish_headers(buffer, &i);

        ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

        printf("Getting Set LockingRange1 Result:\n");
        memset(response, 0, sizeof(response));
        ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);

        // -> []
        i = 0;
        i += sizeof(struct HeadersStruct);
        i += 1; // start list token
        i += 1; // end list token
        i += 1; // end of data token
        // method status list
        printf("method status code: %s (%i)\n", MSC_to_string(response[i + 1]), response[i + 1]);
        printf("\n");
    }

    // char correct_key = 0;
    // if (rc == 0) {
    //     printf("Retrieves the UID of the range’s media encryption key:\n");
    //     memset(buffer, 0, sizeof(buffer));
    //     i = 0;
    //     prepare_headers(buffer, &i, SPSessionID, HostSessionID);
    //     locking_range_get(buffer, &i, locking_range_uid, LOCKING_TABLE_ACTIVE_KEY, LOCKING_TABLE_ACTIVE_KEY);
    //     finish_headers(buffer, &i);
    //     ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

    //     memset(response, 0, sizeof(response));
    //     ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);

    //     i = 0;
    //     i += sizeof(struct HeadersStruct);
    //     i += 1; // start list token
    //     i += 1; // start list token
    //     i += 1; // start name token
    //     i += 1; // tiny atom token - name
    //     i += 1; // short atom token - length 8

    //     printf("found    %02x %02x %02x %02x %02x %02x %02x %02x\n", response[i + 0], response[i + 1], response[i + 2],
    //            response[i + 3], response[i + 4], response[i + 5], response[i + 6], response[i + 7]);
    //     printf("assuming 00 00 08 06 00 03 NN NN\n");
    //     correct_key = response[i + 0] == 0x00 && response[i + 1] == 0x00 && response[i + 2] == 0x08 &&
    //                   response[i + 3] == 0x06 && response[i + 4] == 0x00 && response[i + 5] == 0x03;
    //     ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);
    //     for (int x = 0 ; x < 256; ++x) {
    //         printf("%02x ", response[x]);
    //     }
    //     printf("\n");
    //     // 0c 00 00 f1 00 00 00 00
    //     i += 8;
    //     i += 1; // end name token
    //     i += 1; // end list token
    //     i += 1; // end list token
    //     i += 1; // end of data token
    //     // method status list
    //     printf("method status code: %s (%i)\n", MSC_to_string(response[i + 1]), response[i + 1]);
    //     printf("\n");
    // }
    
    // if (rc == 0 && !correct_key) {

    // }

    // if (rc == 0) {
    //     // Performs a Secure Erase of the range
    //     printf("Sending Genkey – K_AES_256_Range1_Key:\n");
    //     memset(buffer, 0, sizeof(buffer));
    //     i = 0;
    //     prepare_headers(buffer, &i, SPSessionID, HostSessionID);
    //     size_t j = i;
    //     {
    //         size_t *i = &j;
    //         call_token(buffer, i);
    //         short_atom(buffer, i, 1, "\x00\x00\x08\x06\x00\x03\x00\x01", 8);
    //         short_atom(buffer, i, 1, "\x00\x00\x00\x06\x00\x00\x00\x10", 8);
    //         start_list(buffer, i);
    //         end_list(buffer, i);
    //         end_of_data(buffer, i);
    //         method_status_list(buffer, i);
    //     }
    //     i = j;
    //     finish_headers(buffer, &i);
    //     ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

    //     printf("Getting Genkey – K_AES_256_Range1_Key Result:\n");
    //     memset(response, 0, sizeof(response));
    //     ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);
    //     for (int x = 0 ; x < 256; ++x) {
    //         printf("%02x ", response[x]);
    //     }
    //     printf("\n");
    // }

    if (rc == 0) {
        // Gives access to multiple users to read-unlock the range (User1 and User2)
        printf("Sending give access to read-unlock:\n");
        memset(buffer, 0, sizeof(buffer));
        i = 0;
        prepare_headers(buffer, &i, SPSessionID, HostSessionID);
        size_t j = i;
        {
            size_t *i = &j;
            call_token(buffer, i);
            char ace_uid[9] = "\x00\x00\x00\x08\x00\x03\xe0\x00";
            ace_uid[7] = locking_range_uid;
            short_atom(buffer, i, 1, ace_uid, 8);
            short_atom(buffer, i, 1, METHOD_UID_SET, 8);
            start_list(buffer, i);
            {
                // "Values" = [...]
                start_name(buffer, i);
                {
                    tiny_atom(buffer, i, 0, 1);
                    // [
                    start_list(buffer, i);
                    {
                        start_name(buffer, i);
                        {
                            tiny_atom(buffer, i, 0, 3); // BooleanExpr
                            start_list(buffer, i);
                            {
                                start_name(buffer, i);
                                {
                                    short_atom(buffer, i, 1, "\x00\x00\x0c\x05", 4); // Authority_object_ref
                                    short_atom(buffer, i, 1, "\x00\x00\x00\x09\x00\x03\x00\x01", 8); // user 1 uid
                                }
                                end_name_list(buffer, i);
                                start_name(buffer, i);
                                {
                                    short_atom(buffer, i, 1, "\x00\x00\x0c\x05", 4); // Authority_object_ref
                                    short_atom(buffer, i, 1, "\x00\x00\x00\x09\x00\x03\x00\x02", 8); // user 2 uid
                                }
                                end_name_list(buffer, i);
                                start_name(buffer, i);
                                {
                                    short_atom(buffer, i, 1, "\x00\x00\x04\x0e", 4); // bolean_ace
                                    tiny_atom(buffer, i, 0, 0x01); // or
                                }
                                end_name_list(buffer, i);
                            }
                            end_list(buffer, i);
                        }
                        end_name_list(buffer, i);
                    }
                    // ]
                    end_list(buffer, i);
                }
                end_name_list(buffer, i);
            }
            end_list(buffer, i);
            end_of_data(buffer, i);
            method_status_list(buffer, i);
        }
        i = j;
        finish_headers(buffer, &i);
        ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

        printf("Getting ...:\n");
        memset(response, 0, sizeof(response));
        ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);
    }

    if (rc == 0) {
        // Gives access to multiple users to write-unlock the range (User1 and User2)
    }

    if (rc == 0) {
        // Locks for read and write, by setting ReadLocked and WriteLocked for this range to TRUE
    }

    if (rc == 0) {
        finish_session(fd);
    }
}

void setup_user(int fd, int user_uid, unsigned char *admin_pin, int admin_pin_len, unsigned char *user_pin,
                int user_pin_len)
{
    size_t i = 0;
    int rc = 0;

    printf("Unlock range:\n");
    unsigned char buffer[4096] = { 0 };
    unsigned char response[4096] = { 0 };

    if (rc == 0) {
        init_session(fd, LOCKING_SP_UID, 0, admin_pin, admin_pin_len);
    }

    if (rc == 0) {
        // Enable the User1 authority
        printf("Sending Enable the User1 authority:\n");
        memset(buffer, 0, sizeof(buffer));
        i = 0;
        prepare_headers(buffer, &i, SPSessionID, HostSessionID);
        user_enabled_set(buffer, &i, user_uid);
        finish_headers(buffer, &i);
        ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

        printf("Getting Enable the User1 authority:\n");
        memset(response, 0, sizeof(response));
        ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);
    }

    if (rc == 0) {
        // Set User1 pin
        printf("Sending Set User1 pin:\n");
        memset(buffer, 0, sizeof(buffer));
        i = 0;
        prepare_headers(buffer, &i, SPSessionID, HostSessionID);
        user_pin_set(buffer, &i, user_uid, user_pin, user_pin_len);
        finish_headers(buffer, &i);
        ata_trusted(fd, buffer, i, ATA_TRUSTED_SEND, 0x1, base_comID);

        printf("Getting Set User1 pin:\n");
        memset(response, 0, sizeof(response));
        ata_trusted(fd, response, sizeof(response), ATA_TRUSTED_RECEIVE, 0x1, base_comID);
    }

    if (rc == 0) {
        finish_session(fd);
    }
}

#define VAL_UNDEFINED (-1)

static struct argp_option options[] = { { "verify-pin", 'v', "verify_pin" },
                                        { "assign-pin", 'a', "assign_pin" },
                                        { "user", 'u', "user" },
                                        { "locking-range", 'L', "locking_range" },
                                        { "locking-range-start", 's', "start" },
                                        { "locking-range-length", 'l', "length" },
                                        { "read-lock-enabled", 'R', "state" },
                                        { "write-lock-enabled", 'W', "state" },
                                        { "read-locked", 'r', "state" },
                                        { "write-locked", 'w', "state" },
                                        { 0 } };

struct Arguments {
    enum { NONE, CMD_IDENTIFY, CMD_DISCOVERY, CMD_UNLOCK, CMD_SETUP_RANGE, CMD_SETUP_USER } command;
    char *device;
    uint16_t locking_range;
    uint16_t user;
    unsigned char verify_pin[512];
    size_t verify_pin_len;
    unsigned char assign_pin[512];
    size_t assign_pin_len;
    uint16_t locking_range_start;
    uint16_t locking_range_length;
    int8_t read_lock_enabled;
    int8_t write_lock_enabled;
    int8_t read_locked;
    int8_t write_locked;

    size_t parsed_;
} arguments = {
    .read_lock_enabled = VAL_UNDEFINED,
    .write_lock_enabled = VAL_UNDEFINED,
    .read_locked = VAL_UNDEFINED,
    .write_locked = VAL_UNDEFINED,
};

static error_t parse_hex(const char *source, unsigned char *target, size_t *target_len)
{
    while (source[0] != 0) {
        if (source[1] == 0) {
            return 1;
        }

        char source_0 = source[0];
        if (source_0 >= '0' && source_0 <= '9') {
            source_0 = source_0 - '0';
        } else if (source_0 >= 'a' && source_0 <= 'f') {
            source_0 = source_0 - 'a' + 10;
        } else {
            return 1;
        }
        char source_1 = source[1];
        if (source_1 >= '0' && source_1 <= '9') {
            source_1 = source_1 - '0';
        } else if (source_1 >= 'a' && source_1 <= 'f') {
            source_1 = source_1 - 'a' + 10;
        } else {
            return 1;
        }
        target[0] = source_0 << 4 | source_1;

        source += 2;
        target += 1;
        *target_len += 1;
    }

    return 0;
}

static error_t parse_bool(const char *source, int8_t *target)
{
    if (source[0] == '0' && source[1] == 0) {
        *target = 0;
    } else if (source[0] == '1' && source[1] == 0) {
        *target = 1;
    } else {
        return 1;
    }

    return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct Arguments *args = state->input;

    switch (key) {
    case 'u':
        args->user = strtol(arg, NULL, 10);
        break;
    case 'L':
        args->locking_range = strtol(arg, NULL, 10);
        break;
    case 's':
        args->locking_range_start = strtol(arg, NULL, 10);
        break;
    case 'l':
        args->locking_range_length = strtol(arg, NULL, 10);
        break;
    case 'v':
        return parse_hex(arg, args->verify_pin, &args->verify_pin_len);
    case 'a':
        return parse_hex(arg, args->assign_pin, &args->assign_pin_len);
    case 'R':
        return parse_bool(arg, &args->read_lock_enabled);
    case 'W':
        return parse_bool(arg, &args->write_lock_enabled);
    case 'r':
        return parse_bool(arg, &args->read_locked);
    case 'w':
        return parse_bool(arg, &args->write_locked);
    case ARGP_KEY_ARG:
        switch (args->parsed_) {
        case 0:
            if (strcmp(arg, "identify") == 0) {
                args->command = CMD_IDENTIFY;
            } else if (strcmp(arg, "discovery") == 0) {
                args->command = CMD_DISCOVERY;
            } else if (strcmp(arg, "unlock") == 0) {
                args->command = CMD_UNLOCK;
            } else if (strcmp(arg, "setup_range") == 0) {
                args->command = CMD_SETUP_RANGE;
            } else if (strcmp(arg, "setup_user") == 0) {
                args->command = CMD_SETUP_USER;
            } else {
                return ARGP_ERR_UNKNOWN;
            }
            break;
        case 1:
            args->device = arg;
            dev = arg;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
        }
        args->parsed_ += 1;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct argp argp = { options, parse_opt, "device", "Tool for controlling OPAL-based disks.", 0, 0, 0 };
    error_t err = argp_parse(&argp, argc, argv, 0, 0, &arguments);
    if (err != 0 || arguments.parsed_ < 2) {
        printf("could not parse args || not enough args\n");
        return 1;
    }

    int fd = open(arguments.device, O_RDWR);

    if (arguments.command == CMD_IDENTIFY) {
        return nvme_identify(fd);
    } else if (arguments.command == CMD_DISCOVERY) {
        ata_discovery(fd, 1);
    } else if (arguments.command == CMD_UNLOCK) {
        unlock_range(fd, arguments.locking_range, arguments.user, arguments.read_lock_enabled,
                     arguments.write_lock_enabled, arguments.read_locked, arguments.write_locked, arguments.verify_pin,
                     arguments.verify_pin_len);
    } else if (arguments.command == CMD_SETUP_RANGE) {
        setup_range(fd, arguments.locking_range, arguments.verify_pin, arguments.verify_pin_len, arguments.locking_range_start, arguments.locking_range_length);
    } else if (arguments.command == CMD_SETUP_USER) {
        setup_user(fd, arguments.user, arguments.verify_pin, arguments.verify_pin_len, arguments.assign_pin,
                   arguments.assign_pin_len);
    } else {
        printf("invalid command\n");

        err = 1;
    }

    close(fd);

    return err;
}
