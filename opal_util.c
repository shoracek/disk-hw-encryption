#include <linux/nvme_ioctl.h>
#include <linux/fscrypt.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

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
    uint16_t feature_code;
    uint8_t reserved_1 : 4;
    uint8_t version : 4;
    uint8_t length;
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
    uint16_t feature_code;
    uint8_t ssc_minor_version : 4;
    uint8_t feature_descriptor_version : 4;
    uint8_t length;
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

uint32_t swap_endian_32(uint32_t x)
{
    return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24);
}

uint16_t swap_endian_16(uint16_t x)
{
    return ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8);
}

int main(int argc, char **argv)
{
    int err = 0;
    int fd;

    fd = open(argv[1], O_RDONLY | O_CLOEXEC);

    // identify
    {
        struct identify_controller_data response = { 0 };
        struct nvme_admin_cmd cmd = { 0 };

        cmd.opcode = 0x06;
        cmd.cdw10 = 1;
        cmd.data_len = 239; // for some reason, 240 and more writes way too many bytes
        cmd.addr = (unsigned long long)&response;

        err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
        if (err != 0)
            printf("ioctl: %s\n", strerror(errno));

        printf("model_number: '%.*s'\nsn: '%.*s'\nfirmware_revision: '%.*s'\n", sizeof(response.model_number),
               response.model_number, sizeof(response.sn), response.sn, sizeof(response.firmware_revision),
               response.firmware_revision);
    }

    // discovery 0
    {
        unsigned char response[2048] = { 0 };
        struct nvme_admin_cmd cmd = { 0 };

        cmd.opcode = 0x82;
        cmd.cdw10 = 0x1000100;
        cmd.cdw11 = sizeof(response);
        cmd.data_len = sizeof(response);
        cmd.addr = (unsigned long long)&response;

        err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
        if (err != 0)
            printf("ioctl error %s 0x%02x\n", strerror(errno), err);

        struct Level0DiscoveryHeader *header = (void *)response;
        uint32_t offset = sizeof(struct Level0DiscoveryHeader);
        uint32_t total_length = swap_endian_32(header->length);
        printf("len: %i, offset %i\n", total_length, offset);
        while (offset < total_length) {
            struct Level0DiscoverySharedFeature *body = (void *)response + offset;
            uint32_t feature_code = swap_endian_16(body->feature_code);
            offset += body->length + 4;

            if (feature_code == 0x0001) {
                struct Level0DiscoveryTPerFeature *body = (void *)response + offset;
                printf("TPer feature:\n"
                       " - version %i\n"
                       " - comID mgmt supported %i\n"
                       " - streaming supported %i\n"
                       " - buffer mgmt supported %i\n"
                       " - ack nack supported %i\n"
                       " - async supported %i\n"
                       " - sync supported %i\n",
                       body->version, body->comID_mgmt_supported, body->streaming_supported,
                       body->buffer_mgmt_supported, body->ack_nack_supported, body->async_supported,
                       body->sync_supported);
            } else if (feature_code == 0x0203) {
                struct Level0DiscoveryOpal2Feature *body = (void *)response + offset;
                printf("Opal 2 feature:\n"
                       " - minor descriptor version %i\n"
                       " - ssc minor version %i\n"
                       " - base comID %i\n"
                       " - number of comIDs %i\n"
                       " - number of locking SP admin authorities %i\n"
                       " - number of locking SP user authorities %i\n",
                       body->feature_descriptor_version, body->ssc_minor_version, swap_endian_16(body->base_comID),
                       swap_endian_16(body->number_of_comIDs),
                       swap_endian_16(body->number_of_locking_admin_authorities_supported),
                       swap_endian_16(body->number_of_locking_user_authorities_supported));
            } else {
                printf("unimplemented feature %i\n", feature_code);
            }
        }
    }
    return err;
}