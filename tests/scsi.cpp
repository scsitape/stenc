#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "config.h"
#include "scsiencrypt.h"

#include <arpa/inet.h>

using namespace std::literals::string_literals;

/**
 * Compare the SPOUT Set Data Encryption pages generated by stenc to an
 * expected output buffer based on the SCSI command spec.
 *
 * This checks that the program can correctly format command buffers that
 * reflect available input and program options.
 */
TEST_CASE("Disable encryption command", "[scsi]")
{
  const std::uint8_t expected[] {
      // clang-format off
    0x00, 0x10, // page code
    0x00, 0x10, // page length
    0x40, // scope
    0x40, // CEEM, CKOD, RDMC, et al.
    0x00, // encyption mode
    0x00, // decryption mode
    0x01, // algorithm index
    0x00, // key format
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved [8]
    0x00, 0x00 // key length
      // clang-format on
  };

  std::vector<std::uint8_t> key {};
  std::string key_name {};

  auto page_buffer {scsi::make_sde(scsi::encrypt_mode::off,
                                   scsi::decrypt_mode::off, 1u, key, key_name,
                                   scsi::sde_rdmc::algorithm_default, false)};
  auto& page {reinterpret_cast<const scsi::page_sde&>(*page_buffer.get())};
  REQUIRE(sizeof(scsi::page_header) + ntohs(page.length) == sizeof(expected));
  REQUIRE(std::memcmp(&page, expected, sizeof(expected)) == 0);
}

TEST_CASE("Enable encryption command", "[scsi]")
{
  const std::uint8_t expected[] {
      // clang-format off
    0x00, 0x10, // page code
    0x00, 0x30, // page length
    0x40, // scope
    0x40, // CEEM, CKOD, RDMC, et al.
    0x02, // encyption mode
    0x02, // decryption mode
    0x01, // algorithm index
    0x00, // key format
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved [8]
    0x00, 0x20, // key length
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      // clang-format on
  };

  std::vector<std::uint8_t> key {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
      0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  };
  std::string key_name {};

  auto page_buffer {scsi::make_sde(scsi::encrypt_mode::on,
                                   scsi::decrypt_mode::on, 1u, key, key_name,
                                   scsi::sde_rdmc::algorithm_default, false)};
  auto& page {reinterpret_cast<const scsi::page_sde&>(*page_buffer.get())};
  REQUIRE(sizeof(scsi::page_header) + ntohs(page.length) == sizeof(expected));
  REQUIRE(std::memcmp(&page, expected, sizeof(expected)) == 0);
}

TEST_CASE("Enable encryption command with options", "[scsi]")
{
  const std::uint8_t expected[] {
      // clang-format off
    0x00, 0x10, // page code
    0x00, 0x30, // page length
    0x40, // scope
    0x64, // CEEM, CKOD, RDMC, et al.
    0x02, // encyption mode
    0x02, // decryption mode
    0x01, // algorithm index
    0x00, // key format
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved [8]
    0x00, 0x20, // key length
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      // clang-format on
  };

  std::vector<std::uint8_t> key {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
      0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  };
  std::string key_name {};

  auto page_buffer {scsi::make_sde(scsi::encrypt_mode::on,
                                   scsi::decrypt_mode::on, 1u, key, key_name,
                                   scsi::sde_rdmc::enabled, true)};
  auto& page {reinterpret_cast<const scsi::page_sde&>(*page_buffer.get())};
  REQUIRE(sizeof(scsi::page_header) + ntohs(page.length) == sizeof(expected));
  REQUIRE(std::memcmp(&page, expected, sizeof(expected)) == 0);
}

TEST_CASE("Enable encryption command with key name", "[scsi]")
{
  const std::uint8_t expected[] {
      // clang-format off
    0x00, 0x10, // page code
    0x00, 0x40, // page length
    0x40, // scope
    0x40, // CEEM, CKOD, RDMC, et al.
    0x02, // encyption mode
    0x02, // decryption mode
    0x01, // algorithm index
    0x00, // key format
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved [8]
    0x00, 0x20, // key length
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    // KAD
    0x00, // type
    0x00, // authenticated
    0x00, 0x0c, // length
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
      // clang-format on
  };

  std::vector<std::uint8_t> key {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
      0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
  };
  std::string key_name {"Hello world!"s};

  auto page_buffer {scsi::make_sde(scsi::encrypt_mode::on,
                                   scsi::decrypt_mode::on, 1u, key, key_name,
                                   scsi::sde_rdmc::algorithm_default, false)};
  auto& page {reinterpret_cast<const scsi::page_sde&>(*page_buffer.get())};
  REQUIRE(sizeof(scsi::page_header) + ntohs(page.length) == sizeof(expected));
  REQUIRE(std::memcmp(&page, expected, sizeof(expected)) == 0);
}

/**
 * Check the representation of the SPIN Device Encryption Status page
 * matches the values from the raw buffer. Input buffers were observed
 * from device traffic.
 *
 * This checks the SSP_DES structure layout matches the spec, especially
 * with regard to byte ordering and bitfield positions.
 */
TEST_CASE("Interpret device encryption status page", "[scsi]")
{
  const std::uint8_t buffer[] {
      // clang-format off
    0x00, 0x20, // page code
    0x00, 0x24, // length
    0x42, // nexus = 2h, key scope = 2h
    0x02, // encryption mode
    0x02, // decryption mode
    0x01, // algorithm index
    0x00, 0x00, 0x00, 0x01, // key instance counter
    0x18, // parameters control = 1, VCELB = 1, CEEMS = 0, RDMD = 0
    0x00, // KAD format
    0x00, 0x00, // ADSK count
    0x00, 0x00, 0x00, 0x00, // reserved[8]
    0x00, 0x00, 0x00, 0x00,
    // KAD descriptor
    0x00, // descriptor type
    0x01, // authenticated
    0x00, 0x0c, // length
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
      // clang-format on
  };

  auto& page_des {reinterpret_cast<const scsi::page_des&>(buffer)};
  REQUIRE(ntohs(page_des.page_code) == 0x20u);
  REQUIRE(ntohs(page_des.length) == 36u);
  REQUIRE((page_des.scope & scsi::page_des::scope_it_nexus_mask) ==
          std::byte {2u} << scsi::page_des::scope_it_nexus_pos);
  REQUIRE((page_des.scope & scsi::page_des::scope_encryption_mask) ==
          std::byte {2u} << scsi::page_des::scope_encryption_pos);
  REQUIRE(page_des.encryption_mode == scsi::encrypt_mode::on);
  REQUIRE(page_des.decryption_mode == scsi::decrypt_mode::on);
  REQUIRE(page_des.algorithm_index == 1u);
  REQUIRE(ntohl(page_des.key_instance_counter) == 1u);
  REQUIRE((page_des.flags & scsi::page_des::flags_parameters_control_mask) ==
          std::byte {1u} << scsi::page_des::flags_parameters_control_pos);
  REQUIRE((page_des.flags & scsi::page_des::flags_vcelb_mask) ==
          scsi::page_des::flags_vcelb_mask);
  REQUIRE((page_des.flags & scsi::page_des::flags_ceems_mask) == std::byte {});
  REQUIRE((page_des.flags & scsi::page_des::flags_rdmd_mask) == std::byte {});

  auto kads = read_page_kads(page_des);
  REQUIRE(kads.size() == 1u);
  REQUIRE((kads[0]->flags & scsi::kad::flags_authenticated_mask) ==
          std::byte {1u});
  REQUIRE(ntohs(kads[0]->length) == std::strlen("Hello world!"));
  REQUIRE(std::memcmp(kads[0]->descriptor, "Hello world!",
                      ntohs(kads[0]->length)) == 0);
}

TEST_CASE("Interpret next block encryption status page", "[scsi]")
{
  const std::uint8_t buffer[] {
      // clang-format off
    0x00, 0x21, // page code
    0x00, 0x1c, // length
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x05, // compression status = 0, encryption status = 5h
    0x01, // algorithm index
    0x00, // EMES = 0, RDMDS = 0
    0x00, // KAD format
    // KAD descriptor
    0x00, // descriptor type
    0x01, // authenticated
    0x00, 0x0c, // length
    0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
      // clang-format on
  };

  auto& page_nbes {reinterpret_cast<const scsi::page_nbes&>(buffer)};
  REQUIRE(ntohs(page_nbes.page_code) == 0x21u);
  REQUIRE(ntohs(page_nbes.length) == 28u);
  REQUIRE((page_nbes.status & scsi::page_nbes::status_compression_mask) ==
          std::byte {});
  REQUIRE((page_nbes.status & scsi::page_nbes::status_encryption_mask) ==
          std::byte {5u} << scsi::page_nbes::status_encryption_pos);
  REQUIRE(page_nbes.algorithm_index == 1u);
  REQUIRE((page_nbes.flags & scsi::page_nbes::flags_emes_mask) == std::byte {});
  REQUIRE((page_nbes.flags & scsi::page_nbes::flags_rdmds_mask) ==
          std::byte {});

  auto kads = read_page_kads(page_nbes);
  REQUIRE(kads.size() == 1u);
  REQUIRE((kads[0]->flags & scsi::kad::flags_authenticated_mask) ==
          std::byte {1u});
  REQUIRE(ntohs(kads[0]->length) == std::strlen("Hello world!"));
  REQUIRE(std::memcmp(kads[0]->descriptor, "Hello world!",
                      ntohs(kads[0]->length)) == 0);
}

TEST_CASE("Interpret data encryption capabilties page", "[scsi]")
{
  const std::uint8_t buffer[] {
      // clang-format off
    0x00, 0x10, // page code
    0x00, 0x3c, // length
    0x09, // EXTDECC and CFG_P
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // algorithm 1
    0x01,
    0x00,
    0x00, 0x14,
    0x8a, // capabilties
    0x8c,
    0x00, 0x20,
    0x00, 0x3c,
    0x00, 0x20,
    0xed,
    0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x01, 0x00, 0x14,
    // algorithm 2
    0x02,
    0x00,
    0x00, 0x14,
    0x8a, // capabilties
    0x8f,
    0x00, 0x20,
    0x00, 0x3c,
    0x00, 0x20,
    0xd9,
    0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x01, 0x00, 0x10,
      // clang-format on
  };
  static_assert(sizeof(buffer) == sizeof(scsi::page_dec) +
                                      2 * sizeof(scsi::algorithm_descriptor));

  auto& page_dec {reinterpret_cast<const scsi::page_dec&>(buffer)};
  REQUIRE(ntohs(page_dec.page_code) == 0x10u);
  REQUIRE(ntohs(page_dec.length) == 60u);

  REQUIRE((page_dec.flags & scsi::page_dec::flags_extdecc_mask) ==
          std::byte {2u} << scsi::page_dec::flags_extdecc_pos);
  REQUIRE((page_dec.flags & scsi::page_dec::flags_cfg_p_mask) ==
          std::byte {1u} << scsi::page_dec::flags_cfg_p_pos);

  auto algorithms {read_algorithms(page_dec)};
  REQUIRE(algorithms.size() == 2u);

  auto& algo1 {*algorithms[0]};
  REQUIRE(algo1.algorithm_index == 1u);
  REQUIRE(ntohs(algo1.length) == 20u);
  REQUIRE((algo1.flags1 & scsi::algorithm_descriptor::flags1_avfmv_mask) ==
          scsi::algorithm_descriptor::flags1_avfmv_mask);
  REQUIRE((algo1.flags1 & scsi::algorithm_descriptor::flags1_sdk_c_mask) ==
          std::byte {});
  REQUIRE((algo1.flags1 & scsi::algorithm_descriptor::flags1_mac_c_mask) ==
          std::byte {});
  REQUIRE((algo1.flags1 & scsi::algorithm_descriptor::flags1_delb_c_mask) ==
          std::byte {});
  REQUIRE((algo1.flags1 & scsi::algorithm_descriptor::flags1_decrypt_c_mask) ==
          std::byte {2u} << scsi::algorithm_descriptor::flags1_decrypt_c_pos);
  REQUIRE((algo1.flags1 & scsi::algorithm_descriptor::flags1_encrypt_c_mask) ==
          std::byte {2u} << scsi::algorithm_descriptor::flags1_encrypt_c_pos);

  REQUIRE((algo1.flags2 & scsi::algorithm_descriptor::flags2_avfcp_mask) ==
          std::byte {2u} << scsi::algorithm_descriptor::flags2_avfcp_pos);
  REQUIRE((algo1.flags2 & scsi::algorithm_descriptor::flags2_nonce_mask) ==
          std::byte {});
  REQUIRE((algo1.flags2 & scsi::algorithm_descriptor::flags2_kadf_c_mask) ==
          scsi::algorithm_descriptor::flags2_kadf_c_mask);
  REQUIRE((algo1.flags2 & scsi::algorithm_descriptor::flags2_vcelb_c_mask) ==
          scsi::algorithm_descriptor::flags2_vcelb_c_mask);
  REQUIRE((algo1.flags2 & scsi::algorithm_descriptor::flags2_ukadf_mask) ==
          std::byte {});
  REQUIRE((algo1.flags2 & scsi::algorithm_descriptor::flags2_akadf_mask) ==
          std::byte {});

  REQUIRE(ntohs(algo1.maximum_ukad_length) == 32u);
  REQUIRE(ntohs(algo1.maximum_akad_length) == 60u);
  REQUIRE(ntohs(algo1.key_length) == 32u);

  REQUIRE((algo1.flags3 & scsi::algorithm_descriptor::flags3_dkad_c_mask) ==
          std::byte {3u} << scsi::algorithm_descriptor::flags3_dkad_c_pos);
  REQUIRE((algo1.flags3 & scsi::algorithm_descriptor::flags3_eemc_c_mask) ==
          std::byte {2u} << scsi::algorithm_descriptor::flags3_eemc_c_pos);
  REQUIRE((algo1.flags3 & scsi::algorithm_descriptor::flags3_rdmc_c_mask) ==
          std::byte {6u} << scsi::algorithm_descriptor::flags3_rdmc_c_pos);
  REQUIRE((algo1.flags3 & scsi::algorithm_descriptor::flags3_earem_mask) ==
          scsi::algorithm_descriptor::flags3_earem_mask);

  REQUIRE((algo1.maximum_eedk_count &
           scsi::algorithm_descriptor::maximum_eedk_count_mask) == 0u);
  REQUIRE(ntohs(algo1.msdk_count) == 0u);
  REQUIRE(ntohs(algo1.maximum_eedk_size) == 0u);
  REQUIRE(ntohl(algo1.security_algorithm_code) == 0x00010014u);

  auto& algo2 {*algorithms[1]};
  REQUIRE(algo2.algorithm_index == 2u);
  REQUIRE(ntohs(algo2.length) == 20u);
  REQUIRE((algo2.flags1 & scsi::algorithm_descriptor::flags1_avfmv_mask) ==
          scsi::algorithm_descriptor::flags1_avfmv_mask);
  REQUIRE((algo2.flags1 & scsi::algorithm_descriptor::flags1_sdk_c_mask) ==
          std::byte {});
  REQUIRE((algo2.flags1 & scsi::algorithm_descriptor::flags1_mac_c_mask) ==
          std::byte {});
  REQUIRE((algo2.flags1 & scsi::algorithm_descriptor::flags1_delb_c_mask) ==
          std::byte {});
  REQUIRE((algo2.flags1 & scsi::algorithm_descriptor::flags1_decrypt_c_mask) ==
          std::byte {2u} << scsi::algorithm_descriptor::flags1_decrypt_c_pos);
  REQUIRE((algo2.flags1 & scsi::algorithm_descriptor::flags1_encrypt_c_mask) ==
          std::byte {2u} << scsi::algorithm_descriptor::flags1_encrypt_c_pos);

  REQUIRE((algo2.flags2 & scsi::algorithm_descriptor::flags2_avfcp_mask) ==
          std::byte {2u} << scsi::algorithm_descriptor::flags2_avfcp_pos);
  REQUIRE((algo2.flags2 & scsi::algorithm_descriptor::flags2_nonce_mask) ==
          std::byte {});
  REQUIRE((algo2.flags2 & scsi::algorithm_descriptor::flags2_kadf_c_mask) ==
          scsi::algorithm_descriptor::flags2_kadf_c_mask);
  REQUIRE((algo2.flags2 & scsi::algorithm_descriptor::flags2_vcelb_c_mask) ==
          scsi::algorithm_descriptor::flags2_vcelb_c_mask);
  REQUIRE((algo2.flags2 & scsi::algorithm_descriptor::flags2_ukadf_mask) ==
          scsi::algorithm_descriptor::flags2_ukadf_mask);
  REQUIRE((algo2.flags2 & scsi::algorithm_descriptor::flags2_akadf_mask) ==
          scsi::algorithm_descriptor::flags2_akadf_mask);

  REQUIRE(ntohs(algo2.maximum_ukad_length) == 32u);
  REQUIRE(ntohs(algo2.maximum_akad_length) == 60u);
  REQUIRE(ntohs(algo2.key_length) == 32u);

  REQUIRE((algo2.flags3 & scsi::algorithm_descriptor::flags3_dkad_c_mask) ==
          std::byte {3u} << scsi::algorithm_descriptor::flags3_dkad_c_pos);
  REQUIRE((algo2.flags3 & scsi::algorithm_descriptor::flags3_eemc_c_mask) ==
          std::byte {1u} << scsi::algorithm_descriptor::flags3_eemc_c_pos);
  REQUIRE((algo2.flags3 & scsi::algorithm_descriptor::flags3_rdmc_c_mask) ==
          std::byte {4u} << scsi::algorithm_descriptor::flags3_rdmc_c_pos);
  REQUIRE((algo2.flags3 & scsi::algorithm_descriptor::flags3_earem_mask) ==
          scsi::algorithm_descriptor::flags3_earem_mask);

  REQUIRE((algo2.maximum_eedk_count &
           scsi::algorithm_descriptor::maximum_eedk_count_mask) == 0u);
  REQUIRE(ntohs(algo2.msdk_count) == 0u);
  REQUIRE(ntohs(algo2.maximum_eedk_size) == 0u);
  REQUIRE(ntohl(algo2.security_algorithm_code) == 0x00010010u);
}
