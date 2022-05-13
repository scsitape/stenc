/*
Header file to send and recieve SPIN/SPOUT commands to SCSI device

Original program copyright 2010 John D. Coleman

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#ifndef _SCSIENC_H
#define _SCSIENC_H

#include <array>
#include <bitset>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include <arpa/inet.h>

#ifdef HAVE_SYS_MACHINE_H
#include <sys/machine.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

constexpr size_t SSP_KEY_LENGTH = 0X20;
constexpr size_t SSP_DESCRIPTOR_LENGTH = 1024;
constexpr size_t SSP_KAD_HEAD_LENGTH = 4;
constexpr size_t SSP_PAGE_ALLOCATION = 8192;
constexpr size_t SSP_UKAD_LENGTH = 0x1e;

constexpr uint8_t KAD_TYPE_UKAD = 0x00;
constexpr uint8_t KAD_TYPE_AKAD = 0x01;
constexpr uint8_t KAD_TYPE_NONCE = 0x02;
constexpr uint8_t KAD_TYPE_META = 0x03;

constexpr uint8_t RDMC_PROTECT = 0x03;
constexpr uint8_t RDMC_UNPROTECT = 0x02;
constexpr uint8_t RDMC_DEFAULT = 0x00;

// outputs hex in a 2 digit pair
#define HEX(x)                                                                 \
    std::right << std::setw(2) << std::setfill('0') << std::hex << (int)(x) << std::setfill(' ')
// macro for a byte swapped short
constexpr uint16_t BSSHORT(const uint8_t *p)
{
  return static_cast<uint16_t>(p[0]) << 8 | p[1];
}
// macro for a byte swapped int
constexpr uint32_t BSLONG(const uint8_t *p)
{
  return static_cast<uint32_t>(p[0]) << 24 |
         static_cast<uint32_t>(p[1]) << 16 |
         static_cast<uint32_t>(p[2]) << 8 |
         static_cast<uint32_t>(p[3]);
}

#ifdef BYTE_ORDER
#define STENC_BYTE_ORDER BYTE_ORDER
#endif
#ifndef STENC_BYTE_ORDER
#ifdef __BYTE_ORDER
#define STENC_BYTE_ORDER __BYTE_ORDER
#endif
#endif

#ifdef BIG_ENDIAN
#define STENC_TYPE_BIG_ENDIAN BIG_ENDIAN
#endif
#ifndef STENC_TYPE_BIG_ENDIAN
#ifdef __BIG_ENDIAN
#define STENC_TYPE_BIG_ENDIAN __BIG_ENDIAN
#endif
#endif

#if STENC_BYTE_ORDER == STENC_TYPE_BIG_ENDIAN
#define STENC_BIG_ENDIAN 1
#else
#define STENC_BIG_ENDIAN 0
#endif


namespace scsi {

enum class encrypt_mode: std::uint8_t {
  off = 0u,
  external = 1u,
  on = 2u,
};

enum class decrypt_mode: std::uint8_t {
  off = 0u,
  raw = 1u,
  on = 2u,
  mixed = 3u,
};

// key-associated data
struct __attribute__((packed)) kad {
  std::uint8_t type;
  std::byte flags;
  static constexpr auto flags_authenticated_pos {0u};
  static constexpr std::byte flags_authenticated_mask {7u << flags_authenticated_pos};
  std::uint16_t length;
  std::uint8_t descriptor[];
};
static_assert(sizeof(kad) == 4u);

// common 4-byte header of all SP-IN and SP-OUT pages
struct __attribute__((packed)) page_header {
  std::uint16_t page_code;
  std::uint16_t length;
};
static_assert(sizeof(page_header) == 4u);

// device encryption status page
struct __attribute__((packed)) page_des {
  std::uint16_t page_code;
  std::uint16_t length;
  std::byte scope;
  static constexpr auto scope_it_nexus_pos {5u};
  static constexpr std::byte scope_it_nexus_mask {7u << scope_it_nexus_pos};
  static constexpr auto scope_encryption_pos {0u};
  static constexpr std::byte scope_encryption_mask {7u << scope_encryption_pos};
  encrypt_mode encryption_mode;
  decrypt_mode decryption_mode;
  std::uint8_t algorithm_index;
  std::uint32_t key_instance_counter;
  std::byte flags;
  static constexpr auto flags_parameters_control_pos {4u};
  static constexpr std::byte flags_parameters_control_mask {7u << flags_parameters_control_pos};
  static constexpr auto flags_vcelb_pos {3u}; // volume contains encrypted logical blocks
  static constexpr std::byte flags_vcelb_mask {1u << flags_vcelb_pos};
  static constexpr auto flags_ceems_pos {1u}; // check external encryption mode status
  static constexpr std::byte flags_ceems_mask {3u << flags_ceems_pos};
  static constexpr auto flags_rdmd_pos {0u}; // raw decryption mode disabled
  static constexpr std::byte flags_rdmd_mask {1u << flags_rdmd_pos};
  std::uint8_t kad_format;
  std::uint16_t asdk_count;
  std::byte reserved[8];
  kad kads[];
};
static_assert(sizeof(page_des) == 24u);

using page_buffer = std::uint8_t[SSP_PAGE_ALLOCATION];

// set data encryption page
struct __attribute__((packed)) page_sde {
  std::uint16_t page_code;
  std::uint16_t length;
  std::byte control;
  static constexpr auto control_scope_pos {5u};
  static constexpr std::byte control_scope_mask {7u << control_scope_pos};
  static constexpr auto control_lock_pos {0u};
  static constexpr std::byte control_lock_mask {1u << control_lock_pos};
  std::byte flags;
  static constexpr auto flags_ceem_pos {6u}; // check external encryption mode
  static constexpr std::byte flags_ceem_mask {3u << flags_ceem_pos};
  static constexpr auto flags_rdmc_pos {4u}; // raw decryption mode control
  static constexpr std::byte flags_rdmc_mask {3u << flags_rdmc_pos};
  static constexpr auto flags_sdk_pos {3u}; // supplemental decryption key
  static constexpr std::byte flags_sdk_mask {1u << flags_sdk_pos};
  static constexpr auto flags_ckod_pos {2u}; // clear key on demount
  static constexpr std::byte flags_ckod_mask {1u << flags_ckod_pos};
  static constexpr auto flags_ckorp_pos {1u}; // clear key on reservation preempt
  static constexpr std::byte flags_ckorp_mask {1u << flags_ckorp_pos};
  static constexpr auto flags_ckorl_pos {0u}; // clear key on reservation loss
  static constexpr std::byte flags_ckorl_mask {1u << flags_ckorl_pos};
  encrypt_mode encryption_mode;
  decrypt_mode decryption_mode;
  std::uint8_t algorithm_index;
  std::uint8_t key_format;
  std::uint8_t kad_format;
  std::byte reserved[7];
  std::uint16_t key_length;
  std::uint8_t key[];
};
static_assert(sizeof(page_sde) == 20u);

enum class sde_rdmc: std::uint8_t {
  algorithm_default = 0u << page_sde::flags_rdmc_pos,
  enabled = 2u << page_sde::flags_rdmc_pos,
  disabled = 3u << page_sde::flags_rdmc_pos,
};

// next block encryption status page
struct __attribute__((packed)) page_nbes {
  std::uint16_t page_code;
  std::uint16_t length;
  std::uint64_t logical_object_number;
  std::byte status;
  static constexpr auto status_compression_pos {4u};
  static constexpr std::byte status_compression_mask {15u << status_compression_pos};
  static constexpr auto status_encryption_pos {0u};
  static constexpr std::byte status_encryption_mask {15u << status_encryption_pos};
  std::uint8_t algorithm_index;
  std::byte flags;
  static constexpr auto flags_emes_pos {1u}; // encryption mode external status
  static constexpr std::byte flags_emes_mask {1u << flags_emes_pos};
  static constexpr auto flags_rdmds_pos {0u}; // raw decryption mode disabled status
  static constexpr std::byte flags_rdmds_mask {1u << flags_rdmds_pos};
  std::uint8_t kad_format;
  kad kads[];
};
static_assert(sizeof(page_nbes) == 16u);

struct __attribute__((packed)) algorithm_descriptor {
  std::uint8_t algorithm_index;
  std::byte reserved1;
  std::uint16_t length;
  std::byte flags1;
  static constexpr auto flags1_avfmv_pos {7u}; // algorithm valid for mounted volume
  static constexpr std::byte flags1_avfmv_mask {1u << flags1_avfmv_pos};
  static constexpr auto flags1_sdk_c_pos {6u}; // supplemental decryption key capable
  static constexpr std::byte flags1_sdk_c_mask {1u << flags1_sdk_c_pos};
  static constexpr auto flags1_mac_c_pos {5u}; // message authentication code capable
  static constexpr std::byte flags1_mac_c_mask {1u << flags1_mac_c_pos};
  static constexpr auto flags1_delb_c_pos {4u}; // distinguish encrypted logical block capable
  static constexpr std::byte flags1_delb_c_mask {1u << flags1_delb_c_pos};
  static constexpr auto flags1_decrypt_c_pos {2u}; // decryption capabilities
  static constexpr std::byte flags1_decrypt_c_mask {3u << flags1_decrypt_c_pos};
  static constexpr auto flags1_encrypt_c_pos {0u}; // encryption capabilities
  static constexpr std::byte flags1_encrypt_c_mask {3u << flags1_encrypt_c_pos};
  std::byte flags2;
  static constexpr auto flags2_avfcp_pos {6u}; // algorithm valid for current logical position
  static constexpr std::byte flags2_avfcp_mask {3u << flags2_avfcp_pos};
  static constexpr auto flags2_nonce_pos {4u}; // nonce capabilities
  static constexpr std::byte flags2_nonce_mask {3u << flags2_nonce_pos};
  static constexpr auto flags2_kadf_c_pos {3u}; // KAD format capable
  static constexpr std::byte flags2_kadf_c_mask {1u << flags2_kadf_c_pos};
  static constexpr auto flags2_vcelb_c_pos {2u}; // volume contains encrypted logical blocks capable
  static constexpr std::byte flags2_vcelb_c_mask {1u << flags2_vcelb_c_pos};
  static constexpr auto flags2_ukadf_pos {1u}; // U-KAD fixed
  static constexpr std::byte flags2_ukadf_mask {1u << flags2_ukadf_pos};
  static constexpr auto flags2_akadf_pos {0u}; // A-KAD fixed
  static constexpr std::byte flags2_akadf_mask {1u << flags2_akadf_pos};
  std::uint16_t maximum_ukad_length;
  std::uint16_t maximum_akad_length;
  std::uint16_t key_length;
  std::byte flags3;
  static constexpr auto flags3_dkad_c_pos {6u}; // decryption capabilities
  static constexpr std::byte flags3_dkad_c_mask {3u << flags3_dkad_c_pos};
  static constexpr auto flags3_eemc_c_pos {4u}; // external encryption mode control capabilities
  static constexpr std::byte flags3_eemc_c_mask {3u << flags3_eemc_c_pos};
  static constexpr auto flags3_rdmc_c_pos {1u}; // raw decryption mode control capabilities
  static constexpr std::byte flags3_rdmc_c_mask {7u << flags3_rdmc_c_pos};
  static constexpr auto flags3_earem_pos {0u}; // encryption algorithm records encryption mode
  static constexpr std::byte flags3_earem_mask {1u << flags3_earem_pos};
  std::uint8_t maximum_eedk_count;
  static constexpr auto maximum_eedk_count_pos {0u};
  static constexpr std::uint8_t maximum_eedk_count_mask {15u << maximum_eedk_count_pos};
  std::uint16_t msdk_count;
  std::uint16_t maximum_eedk_size;
  std::byte reserved2[2];
  std::uint32_t security_algorithm_code;
};
static_assert(sizeof(algorithm_descriptor) == 24u);

// device encryption capabilities page
struct __attribute__((packed)) page_dec {
  std::uint16_t page_code;
  std::uint16_t length;
  std::byte flags;
  static constexpr auto flags_extdecc_pos {2u}; // external data encryption control capable
  static constexpr std::byte flags_extdecc_mask {3u << flags_extdecc_pos};
  static constexpr auto flags_cfg_p_pos {0u}; // configuration prevented
  static constexpr std::byte flags_cfg_p_mask {3u << flags_cfg_p_pos};
  std::byte reserved[15];
  algorithm_descriptor ads[];
};
static_assert(sizeof(page_dec) == 20u);

struct __attribute__((packed)) inquiry_data {
  // bitfield definitions omitted since stenc only uses vendor and product info
  std::byte peripheral;
  std::byte flags1;
  std::uint8_t version;
  std::byte flags2;
  std::uint8_t additional_length;
  std::byte flags3;
  std::byte flags4;
  std::byte flags5;
  char vendor[8];
  char product_id[16];
  char product_rev[4];
  std::uint8_t vendor_specific[20];
  std::byte reserved1[2];
  std::uint16_t version_descriptor[8];
  std::byte reserved2[22];
};
static_assert(sizeof(inquiry_data) == 96u);

struct __attribute__((packed)) sense_data {
  std::byte response;
  static constexpr auto response_valid_pos {7u};
  static constexpr std::byte response_valid_mask {1u << response_valid_pos};
  static constexpr auto response_code_pos {0u};
  static constexpr std::byte response_code_mask {127u << response_code_pos};
  std::byte reserved;
  std::byte flags;
  static constexpr auto flags_filemark_pos {7u};
  static constexpr std::byte flags_filemark_mask {1u << flags_filemark_pos};
  static constexpr auto flags_eom_pos {6u}; // end of medium
  static constexpr std::byte flags_eom_mask {1u << flags_eom_pos};
  static constexpr auto flags_ili_pos {5u}; // incorrect length indicator
  static constexpr std::byte flags_ili_mask {1u << flags_ili_pos};
  static constexpr auto flags_sdat_ovfl_pos {4u}; // sense data overflow
  static constexpr std::byte flags_sdat_ovfl_mask {1u << flags_sdat_ovfl_pos};
  static constexpr auto flags_sense_key_pos {0u};
  static constexpr std::byte flags_sense_key_mask {15u << flags_sense_key_pos};
  std::uint8_t information[4];
  std::uint8_t additional_sense_length;
  std::uint8_t command_specific_information[4];
  std::uint8_t additional_sense_code;
  std::uint8_t additional_sense_qualifier;
  std::uint8_t field_replaceable_unit_code;
  std::uint8_t sense_key_specific[3];
  std::uint8_t additional_sense_bytes[];
  static constexpr auto maximum_size {252u}; // per SPC-5
};
static_assert(sizeof(sense_data) == 18u);

// declared as std::array instead of std::uint8_t[] because
// std::unique_ptr does not allow construction of fixed-sized arrays
using sense_buffer = std::array<std::uint8_t, sense_data::maximum_size>;

class scsi_error: public std::runtime_error {
  public:
    explicit scsi_error(std::unique_ptr<sense_buffer>&& buf) :
      sense_buf {std::move(buf)}, std::runtime_error {""} {}
    const sense_data& get_sense() const { return reinterpret_cast<sense_data&>(*sense_buf->data()); }

  private:
    std::unique_ptr<sense_buffer> sense_buf;
};

// Extract pointers to kad structures within a variable-length page.
// Page must have a page_header layout
template<typename Page>
std::vector<const kad *> read_page_kads(const Page& page)
{
  const auto start {reinterpret_cast<const uint8_t*>(&page)};
  auto it {start + sizeof(Page)};
  const auto end {start + ntohs(page.length) + sizeof(page_header)};
  std::vector<const kad *> v {};

  while (it < end) {
    auto elem {reinterpret_cast<const kad *>(it)};
    v.push_back(elem);
    it += ntohs(elem->length) + sizeof(kad);
  }
  return v;
}

inquiry_data get_inquiry(const std::string& device);
// Get data encryption status page
void get_des(const std::string& device, const std::uint8_t *buffer,
             std::size_t length);
// Get next block encryption status page
void get_nbes(const std::string& device, const std::uint8_t *buffer,
              std::size_t length);
// Get device encryption capabilities
void get_dec(const std::string& device, const std::uint8_t *buffer,
             std::size_t length);
// Fill out a set data encryption page with parameters.
// Result is allocated and returned as a std::unique_ptr and should
// be sent to the device using scsi::write_sde
std::unique_ptr<const std::uint8_t[]> make_sde(encrypt_mode enc_mode,
                                               decrypt_mode dec_mode,
                                               std::uint8_t algorithm_index,
                                               const std::vector<std::uint8_t> key,
                                               const std::string& key_name,
                                               sde_rdmc rdmc, bool ckod);
// Write set data encryption parameters to device
void write_sde(const std::string& device, const std::uint8_t *sde_buffer);
void print_sense_data(std::ostream& os, const sense_data& sd);
}


struct SSP_PAGE_DES {
  unsigned char pageCode[2];
  unsigned char length[2];

#if STENC_BIG_ENDIAN == 1
  unsigned char nexusScope : 3;
  unsigned char res_bits_1 : 2;
  unsigned char keyScope : 3;
#else
  unsigned char keyScope : 3;
  unsigned char res_bits_1 : 2;
  unsigned char nexusScope : 3;
#endif
  unsigned char encryptionMode;
  unsigned char decryptionMode;
  unsigned char algorithmIndex;
  unsigned char keyInstance[4];
#if STENC_BIG_ENDIAN == 1
  unsigned char res_bits_2 : 1;
  unsigned char parametersControl : 3;
  unsigned char VCELB : 1;
  unsigned char CEEMS : 2;
  unsigned char RDMD : 1;
#else

  unsigned char RDMD : 1;
  unsigned char CEEMS : 2;
  unsigned char VCELB : 1;
  unsigned char parametersControl : 3;
  unsigned char res_bits_2 : 1;
#endif
  unsigned char res_bits_3;
  unsigned char ASDKCount[2];
  unsigned char res_bits_4[8];

}; // device encryption status page

struct SSP_KAD{
  unsigned char type;
#if STENC_BIG_ENDIAN == 1
  unsigned char res_bits_1 : 5;
  unsigned char authenticated : 3;
#else
  unsigned char authenticated : 3;
  unsigned char res_bits_1 : 5;
#endif
  unsigned char descriptorLength[2];
  unsigned char descriptor[SSP_DESCRIPTOR_LENGTH]; // will actually be the size
                                                   // of descriptorLength
};


struct SSP_PAGE_BUFFER {
  unsigned char pageCode[2];
  unsigned char length[2];
  unsigned char buffer[SSP_PAGE_ALLOCATION];
}; // generic ssp page buffer


struct SSP_PAGE_SDE { // structure for setting data encryption
  unsigned char pageCode[2];
  unsigned char length[2];

#if STENC_BIG_ENDIAN == 1
  unsigned char scope : 3;
  unsigned char res_bits_1 : 4;
  unsigned char lock : 1;
#else
  unsigned char lock : 1;
  unsigned char res_bits_1 : 4;
  unsigned char scope : 3;
#endif

#if STENC_BIG_ENDIAN == 1
  unsigned char CEEM : 2;
  unsigned char RDMC : 2;
  unsigned char sdk : 1;
  unsigned char ckod : 1;
  unsigned char ckorp : 1;
  unsigned char ckorl : 1;
#else
  unsigned char ckorl : 1;
  unsigned char ckorp : 1;
  unsigned char ckod : 1;
  unsigned char sdk : 1;
  unsigned char RDMC : 2;
  unsigned char CEEM : 2;
#endif
  unsigned char encryptionMode;
  unsigned char decryptionMode;
  unsigned char algorithmIndex;
  unsigned char keyFormat;
  unsigned char res_bits_2[8];
  unsigned char keyLength[2];
  unsigned char keyData[SSP_KEY_LENGTH];
};


struct SSP_PAGE_NBES {
  unsigned char pageCode[2];
  unsigned char length[2];
  unsigned char log_obj_num[8];
#if STENC_BIG_ENDIAN == 1
  unsigned char compressionStatus : 4;
  unsigned char encryptionStatus : 4;
#else
  unsigned char encryptionStatus : 4;
  unsigned char compressionStatus : 4;
#endif

  unsigned char algorithmIndex;
#if STENC_BIG_ENDIAN == 1
  unsigned char res_bits_1 : 6;
  unsigned char EMES : 1;
  unsigned char RDMDS : 1;
#else
  unsigned char RDMDS : 1;
  unsigned char EMES : 1;
  unsigned char res_bits_1 : 6;
#endif

  unsigned char res_bits_2;
}; // next block encryption status page


struct SCSI_PAGE_INQ {

#if STENC_BIG_ENDIAN == 0
  unsigned char peripheralQualifier : 3;
  unsigned char periphrealDeviceType : 5;
#else
  unsigned char periphrealDeviceType : 5;
  unsigned char peripheralQualifier : 3;
#endif

#if STENC_BIG_ENDIAN == 0
  unsigned char RMB : 1;
  unsigned char res_bits_1 : 7;
#else
  unsigned char res_bits_1 : 7;
  unsigned char RMB : 1;
#endif
  unsigned char Version[1];

#if STENC_BIG_ENDIAN == 0
  unsigned char obs_bits_1 : 2;
  unsigned char NORMACA : 1;
  unsigned char HISUP : 1;
  unsigned char responseDataFormat : 4;
#else
  unsigned char responseDataFormat : 4;
  unsigned char HISUP : 1;
  unsigned char NORMACA : 1;
  unsigned char obs_bits_1 : 2;
#endif

  unsigned char additionalLength[1];

#if STENC_BIG_ENDIAN == 0
  unsigned char SCCS : 1;
  unsigned char ACC : 1;
  unsigned char TPGS : 2;
  unsigned char threePC : 1;
  unsigned char res_bits_2 : 2;
  unsigned char protect : 1;
#else
  unsigned char protect : 1;
  unsigned char res_bits_2 : 2;
  unsigned char threePC : 1;
  unsigned char TPGS : 2;
  unsigned char ACC : 1;
  unsigned char SCCS : 1;
#endif

#if STENC_BIG_ENDIAN == 0
  unsigned char obs_bits_2 : 1;
  unsigned char ENCSERV : 1;
  unsigned char VS : 1;
  unsigned char MULTIP : 1;
  unsigned char MCHNGR : 1;
  unsigned char obs_bits_3 : 2;
  unsigned char ADDR16 : 1;
#else
  unsigned char ADDR16 : 1;
  unsigned char obs_bits_3 : 2;
  unsigned char MCHNGR : 1;
  unsigned char MULTIP : 1;
  unsigned char VS : 1;
  unsigned char ENCSERV : 1;
  unsigned char obs_bits_2 : 1;
#endif

#if STENC_BIG_ENDIAN == 0
  unsigned char obs_bits_4 : 2;
  unsigned char WBUS16 : 1;
  unsigned char SYNC : 1;
  unsigned char obs_bits_5 : 2;
  unsigned char CMDQUE : 1;
  unsigned char VS2 : 1;
#else
  unsigned char VS2 : 1;
  unsigned char CMDQUE : 1;
  unsigned char obs_bits_5 : 2;
  unsigned char SYNC : 1;
  unsigned char WBUS16 : 1;
  unsigned char obs_bits_4 : 2;
#endif

  unsigned char vender[8];
  unsigned char productID[16];
  unsigned char productRev[4];
  unsigned char SN[7];
  unsigned char venderUnique[12];

#if STENC_BIG_ENDIAN == 0
  unsigned char res_bits_3 : 4;
  unsigned char CLOCKING : 2;
  unsigned char QAS : 1;
  unsigned char IUS : 1;
#else
  unsigned char IUS : 1;
  unsigned char QAS : 1;
  unsigned char CLOCKING : 2;
  unsigned char res_bits_3 : 4;
#endif

  unsigned char res_bits_4[1];
  unsigned char versionDescriptor[16];
  unsigned char res_bits_5[22];
  unsigned char copyright[1];
}; // device inquiry response


struct SCSI_PAGE_SENSE {
#if STENC_BIG_ENDIAN == 1
  unsigned char valid : 1;
  unsigned char responseCode : 7;
#else
  unsigned char responseCode : 7;
  unsigned char valid : 1;
#endif
  unsigned char res_bits_1;

#if STENC_BIG_ENDIAN == 1
  unsigned char filemark : 1;
  unsigned char EOM : 1;
  unsigned char ILI : 1;
  unsigned char res_bits_2 : 1;
  unsigned char senseKey : 4;
#else
  unsigned char senseKey : 4;
  unsigned char res_bits_2 : 1;
  unsigned char ILI : 1;
  unsigned char EOM : 1;
  unsigned char filemark : 1;
#endif
  unsigned char information[4];
  unsigned char addSenseLen;
  unsigned char cmdSpecificInfo[4];
  unsigned char addSenseCode;
  unsigned char addSenseCodeQual;
  unsigned char fieldRepUnitCode;
#if STENC_BIG_ENDIAN == 1
  unsigned char sim : 3;    // system information message
  unsigned char bpv : 1;    // bit pointer valid
  unsigned char resvd2 : 2; // reserved
  unsigned char cd : 1;     // control/data
  unsigned char SKSV : 1;

#else
  unsigned char SKSV : 1;
  unsigned char cd : 1;     // control/data
  unsigned char resvd2 : 2; // reserved
  unsigned char bpv : 1;    // bit pointer valid
  unsigned char sim : 3;    // system information message
#endif
  unsigned char field[2]; // field pointer
  unsigned char addSenseData[109];
}; // sense data response

class KAD_CLASS {
public:
  std::vector<SSP_KAD> kads;

protected:
  void loadKADs(const SSP_PAGE_BUFFER *buffer, int start);
};

// class used to parse next block encryption status page
class SSP_NBES : public KAD_CLASS {
public:
  SSP_PAGE_NBES nbes;
  SSP_NBES(const SSP_PAGE_BUFFER *buffer);
};
// class used to parse data encryption status page
class SSP_DES : public KAD_CLASS {
public:
  SSP_PAGE_DES des;
  SSP_DES(const SSP_PAGE_BUFFER *buffer);
};

// enum for SCSIEncryptOptions.cryptMode
enum { CRYPTMODE_OFF, CRYPTMODE_MIXED, CRYPTMODE_ON, CRYPTMODE_RAWREAD };

// used to pass parameters to SCSIWriteEncryptOptions
class SCSIEncryptOptions {
public:
  int rdmc;
  bool CKOD;
  int cryptMode;
  unsigned int algorithmIndex;
  std::vector<uint8_t> cryptoKey;
  std::string keyName;
  SCSIEncryptOptions();
};

// Gets encryption options on the tape drive
SSP_DES *SSPGetDES(const std::string& tapeDevice);
// Gets the encryption status from the tape volume
SSP_NBES *SSPGetNBES(const std::string& tapeDevice, bool retry);
// Writes encryption options to the tape drive
int SCSIInitSDEPage(SCSIEncryptOptions *eOptions,
                    uint8_t *buffer);
bool SCSIWriteEncryptOptions(const std::string& tapeDevice,
                             SCSIEncryptOptions *eOptions);
// Gets device inquiry
SCSI_PAGE_INQ *SCSIGetInquiry(const std::string& tapeDevice);

#endif
