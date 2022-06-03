#include <linux/nvme_ioctl.h>
#include <linux/fscrypt.h>
#include <linux/hdreg.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <scsi/sg.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#define ATA_TRUSTED_RECEIVE 0x5c
#define ATA_TRUSTED_SEND 0x5e
#define TCG_LEVEL_0_DISCOVERY_PROTOCOL_ID 0x01
#define TCG_LEVEL_0_DISCOVERY_COMID 0x0001

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
    An Opal SSC compliant SD SHALL return the followi
    • Feature Code = 0x0001
    • Version = 0x1 or any version that supports the
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

void tcg_discovery_0_process_feature(void *data, int feature_code)
{
    if (feature_code == 0x0001) {
        struct Level0DiscoveryTPerFeature *body = data;
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
        printf("Geometry feature:\n"
               " - logical block size: %i\n"
               " - alignment granularity: %i\n"
               " - lowest alignment LBA: %i\n",
               swap_endian_32(feature->logical_block_size), swap_endian_64(feature->alignment_granularity),
               swap_endian_64(feature->lowest_alignment_LBA));
    } else if (feature_code == 0x0203) {
        struct Level0DiscoveryOpal2Feature *body = data;
        printf("Opal SSC V2.00 Feature:\n"
               " - base comID %i\n"
               " - number of comIDs %i\n"
               " - number of locking SP admin authorities %i\n"
               " - number of locking SP user authorities %i\n",
               swap_endian_16(body->base_comID), swap_endian_16(body->number_of_comIDs),
               swap_endian_16(body->number_of_locking_admin_authorities_supported),
               swap_endian_16(body->number_of_locking_user_authorities_supported));
    } else {
        printf("unimplemented feature %i\n", feature_code);
    }
}

void tcg_discovery_0_process_response(void *data)
{
    struct Level0DiscoveryHeader *header = data;
    uint32_t offset = sizeof(struct Level0DiscoveryHeader);
    uint32_t total_length = swap_endian_32(header->length);

    while (offset < total_length) {
        struct Level0DiscoverySharedFeature *body = data + offset;
        uint32_t feature_code = swap_endian_16(body->feature_code);

        tcg_discovery_0_process_feature(body, feature_code);

        offset += body->length + sizeof(struct Level0DiscoverySharedFeature);
    }
}

int sata_trusted(int fd, uint8_t *response, size_t response_len, int send, int cmd, int protocol, int comID)
{
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
        .trusted_receive.transfer_length = response_len / 4096,
        .trusted_receive.sp_specific = comID,
        .trusted_receive.command = cmd,
    };

    sg_io_hdr_t sg = {
        .interface_id = 'S',
        .dxfer_direction = cmd == ATA_TRUSTED_RECEIVE ? SG_DXFER_FROM_DEV : SG_DXFER_TO_DEV,
        .cmdp = (void *)&cdb,
        .cmd_len = sizeof(cdb),
        .dxferp = response,
        .dxfer_len = response_len,
        .timeout = 10000,
        // todo: figure out sense
    };

    if (ioctl(fd, SG_IO, &sg) < 0) {
        printf("bad ioctl %s\n", strerror(errno));
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

int main(int argc, char **argv)
{
    int err = 0;
    int fd;

    if (strcmp(argv[1], "identify") == 0) {
        fd = open(argv[2], O_RDONLY | O_CLOEXEC);
        return nvme_identify(fd);
    } else if (strcmp(argv[1], "discovery") == 0) {
        fd = open(argv[2], O_RDWR);
        if (fd < 0)
            printf("open error\n");

        uint8_t response[4096] = { 0 };

        sata_trusted(fd, response, sizeof(response), 0, ATA_TRUSTED_RECEIVE, TCG_LEVEL_0_DISCOVERY_PROTOCOL_ID,
                     TCG_LEVEL_0_DISCOVERY_COMID);
        tcg_discovery_0_process_response(response);

        return 0;
    } else {
        printf("invalid command\n");
        return 1;
    }

    return err;
}
