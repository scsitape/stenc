/*
stenc - program to set and retrieve hardware based encryption
        options from certain SCSI devices (i.e. LTO4 Tape drives)

Original program copyright 2010 John D. Coleman

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/
#include <config.h>

#include <charconv>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <sys/mtio.h>
#include <sys/stat.h>
#include <syslog.h>
#include <termios.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "scsiencrypt.h"

static std::optional<std::vector<std::uint8_t>>
key_from_hex_chars(const std::string& s)
{
  auto it = s.data();
  std::vector<std::uint8_t> bytes;

  if (s.size() % 2) { // treated as if there is an implicit leading 0
    std::uint8_t result;
    auto [ptr, ec] {std::from_chars(it, it + 1, result, 16)};
    if (ec != std::errc {}) {
      return {};
    }
    bytes.push_back(result);
    it = ptr;
  }

  while (*it) {
    std::uint8_t result;
    auto [ptr, ec] {std::from_chars(it, it + 2, result, 16)};
    if (ec != std::errc {}) {
      return {};
    }
    bytes.push_back(result);
    it = ptr;
  }
  return bytes;
}

// shows the command usage
static void showUsage()
{
  std::cerr << "Usage: stenc --version | "
               "-f <device> [--detail] [-e <on/mixed/rawread/off> [-k <file>] "
               "[-kd <description>] [-a <index>] [--protect | --unprotect] "
               "[--ckod] ]\n\n"
               "Type 'man stenc' for more information.\n";
}

// exits to shell with an error message
static void errorOut(const std::string& message)
{
  std::cerr << "Error: " << message << "\n";
  showUsage();
  exit(EXIT_FAILURE);
}

static void print_algorithm_name(std::ostream& os, const uint32_t code)
{
  // Reference: SFSC / INCITS 501-2016
  if (0x80010400 <= code && code <= 0x8001FFFF) {
    os << "Vendor specific 0x" << std::setw(8) << std::setfill('0') << std::hex
       << code << std::setfill(' ');
  }
  switch (code) {
  case 0x0001000C:
    os << "AES-256-CBC-HMAC-SHA-1";
    break;
  case 0x00010010:
    os << "AES-256-CCM-128";
    break;
  case 0x00010014:
    os << "AES-256-GCM-128";
    break;
  case 0x00010016:
    os << "AES-256-XTS-HMAC-SHA-512";
    break;
  default:
    os << "Unknown 0x" << std::setw(8) << std::setfill('0') << std::hex << code
       << std::setfill(' ');
  }
}

static void print_algorithms(std::ostream& os, const scsi::page_dec& page)
{
  auto algorithms {scsi::read_algorithms(page)};

  os << "Supported algorithms:\n";

  for (auto ad_ptr: algorithms) {
    auto& ad {*ad_ptr};
    os << std::left << std::setw(5) << (unsigned int) {ad.algorithm_index};
    print_algorithm_name(os, ntohl(ad.security_algorithm_code));
    os.put('\n');

    // Print KAD capabilities and size
    auto dkad_c {static_cast<unsigned int>(
        ad.flags3 & scsi::algorithm_descriptor::flags3_dkad_c_mask)};
    if (dkad_c == 1u << scsi::algorithm_descriptor::flags3_dkad_c_pos) {
      os << std::left << std::setw(5) << ""
         << "Key descriptors not allowed\n";
    } else if (dkad_c) {
      os << std::left << std::setw(5) << "";
      if (dkad_c == 1u << scsi::algorithm_descriptor::flags3_dkad_c_pos) {
        os << "Key descriptors required, ";
      } else {
        os << "Key descriptors allowed, ";
      }
      if ((ad.flags2 & scsi::algorithm_descriptor::flags2_ukadf_mask) ==
          scsi::algorithm_descriptor::flags2_ukadf_mask) {
        os << "fixed ";
      } else {
        os << "maximum ";
      }
      os << std::dec << ntohs(ad.maximum_ukad_length) << " bytes\n";
    }

    // Print raw decryption mode capability:
    auto rdmc_c {static_cast<unsigned int>(
        ad.flags3 & scsi::algorithm_descriptor::flags3_rdmc_c_mask)};
    switch (rdmc_c) {
    case 1u << scsi::algorithm_descriptor::flags3_rdmc_c_pos:
    case 6u << scsi::algorithm_descriptor::flags3_rdmc_c_pos:
      os << std::left << std::setw(5) << "";
      os << "Raw decryption mode not allowed\n";
      break;
    case 4u << scsi::algorithm_descriptor::flags3_rdmc_c_pos:
    case 5u << scsi::algorithm_descriptor::flags3_rdmc_c_pos:
    case 7u << scsi::algorithm_descriptor::flags3_rdmc_c_pos:
      os << std::left << std::setw(5) << "";
      os << "Raw decryption mode allowed, raw read ";
      if (rdmc_c == 4u << scsi::algorithm_descriptor::flags3_rdmc_c_pos) {
        os << "disabled by default\n";
      } else {
        os << "enabled by default\n";
      }
      break;
    }
  }
}

static void print_device_inquiry(std::ostream& os,
                                 const scsi::inquiry_data& iresult)
{
  os << std::left << std::setw(25) << "Vendor:";
  os.write(iresult.vendor, 8);
  os.put('\n');
  os << std::left << std::setw(25) << "Product ID:";
  os.write(iresult.product_id, 16);
  os.put('\n');
  os << std::left << std::setw(25) << "Product Revision:";
  os.write(iresult.product_rev, 4);
  os.put('\n');
}

static void inquiryDrive(const std::string& tapeDevice)
{
  // todo: std::cout should not be used outside main()
  auto iresult {scsi::get_inquiry(tapeDevice)};
  print_device_inquiry(std::cout, iresult);
}

static void print_device_status(std::ostream& os, const scsi::page_des& opt,
                                bool detail)
{
  std::string emode = "unknown";
  os << std::left << std::setw(25) << "Drive Encryption:";
  if (opt.encryption_mode == scsi::encrypt_mode::on && // encrypt
      opt.decryption_mode == scsi::decrypt_mode::on // read only encrypted data
  ) {
    emode = "on";
  }
  if (opt.encryption_mode == scsi::encrypt_mode::on && // encrypt
      opt.decryption_mode ==
          scsi::decrypt_mode::mixed // read encrypted and unencrypted
  ) {
    emode = "mixed";
  }

  if (opt.encryption_mode == scsi::encrypt_mode::on && // encrypt
      opt.decryption_mode ==
          scsi::decrypt_mode::raw // read encrypted and unencrypted
  ) {
    emode = "rawread";
  }

  if (opt.encryption_mode == scsi::encrypt_mode::off && // encrypt
      opt.decryption_mode ==
          scsi::decrypt_mode::off // read encrypted and unencrypted
  ) {
    emode = "off";
  }

  os << emode << "\n";
  if (detail) {
    os << std::left << std::setw(25) << "Drive Output:";
    switch (opt.decryption_mode) {
    case scsi::decrypt_mode::off:
      os << "Not decrypting\n";
      os << std::setw(25) << " "
         << "Raw encrypted data not outputted\n";
      break;
    case scsi::decrypt_mode::raw:
      os << "Not decrypting\n";
      os << std::setw(25) << " "
         << "Raw encrypted data outputted\n";
      break;
    case scsi::decrypt_mode::on:
      os << "Decrypting\n";
      os << std::setw(25) << " "
         << "Unencrypted data not outputted\n";
      break;
    case scsi::decrypt_mode::mixed:
      os << "Decrypting\n";
      os << std::setw(25) << " "
         << "Unencrypted data outputted\n";
      break;
    default:
      os << "Unknown '0x" << std::hex
         << static_cast<unsigned int>(opt.decryption_mode) << "' \n";
      break;
    }
    os << std::setw(25) << "Drive Input:";
    switch (opt.encryption_mode) {
    case scsi::encrypt_mode::off:
      os << "Not encrypting\n";
      break;
    case scsi::encrypt_mode::on:
      os << "Encrypting\n";
      break;
    default:
      os << "Unknown result '0x" << std::hex
         << static_cast<unsigned int>(opt.encryption_mode) << "'\n";
      break;
    }
    if ((opt.flags & scsi::page_des::flags_rdmd_mask) ==
        scsi::page_des::flags_rdmd_mask) {
      os << std::setw(25) << " "
         << "Protecting from raw read\n";
    }

    os << std::setw(25) << "Key Instance Counter:" << std::dec
       << ntohl(opt.key_instance_counter) << "\n";
    if (opt.algorithm_index != 0) {
      os << std::setw(25) << "Encryption Algorithm:" << std::dec
         << static_cast<unsigned int>(opt.algorithm_index) << "\n";
    }
  }
  auto kads {scsi::read_page_kads(opt)};
  for (auto kd: kads) {
    switch (kd->type) {
    case scsi::kad_type::ukad:
      os << std::setw(25) << "Drive Key Desc.(uKAD): ";
      os.write(reinterpret_cast<const char *>(kd->descriptor),
               ntohs(kd->length));
      os.put('\n');
      break;
    case scsi::kad_type::akad:
      os << std::setw(25) << "Drive Key Desc.(aKAD): ";
      os.write(reinterpret_cast<const char *>(kd->descriptor),
               ntohs(kd->length));
      os.put('\n');
      break;
    }
  }
}

static void showDriveStatus(const std::string& tapeDrive, bool detail)
{
  alignas(4) scsi::page_buffer buffer;
  scsi::get_des(tapeDrive, buffer, sizeof(buffer));
  auto& opt {reinterpret_cast<const scsi::page_des&>(buffer)};

  print_device_status(std::cout, opt, detail);
}

static void print_volume_status(std::ostream& os, const scsi::page_nbes& opt)
{
  auto compression_status {static_cast<std::uint8_t>(
      (opt.status & scsi::page_nbes::status_compression_mask) >>
      scsi::page_nbes::status_compression_pos)};
  // From vendor docs, no known drives actually report anything other than 0
  if (compression_status != 0u) {
    os << std::left << std::setw(25) << "Volume Compressed:";
    switch (compression_status) {
    case 0u:
      os << "Drive cannot determine\n";
      break;
    default:
      os << "Unknown result '" << std::hex
         << static_cast<unsigned int>(compression_status) << "'\n";
      break;
    }
  }
  os << std::left << std::setw(25) << "Volume Encryption:";
  auto encryption_status {static_cast<std::uint8_t>(
      (opt.status & scsi::page_nbes::status_encryption_mask) >>
      scsi::page_nbes::status_encryption_pos)};
  auto kads {read_page_kads(opt)};
  switch (encryption_status) {
  case 0u:
  case 1u:
    os << "Unable to determine\n";
    break;
  case 2u:
    os << "Tape position not at a logical block\n";
    break;
  case 3u:
    os << "Not encrypted\n";
    break;
  case 5u:
    os << "Encrypted and able to decrypt\n";
    if ((opt.flags & scsi::page_nbes::flags_rdmds_mask) ==
        scsi::page_nbes::flags_rdmds_mask) {
      os << std::left << std::setw(25) << " Protected from raw read\n";
    }
    break;
  case 6u:
    os << "Encrypted, but unable to decrypt due to invalid key.\n";
    for (auto kd: kads) {
      switch (kd->type) {
      case scsi::kad_type::ukad:
        os << std::setw(25) << "Volume Key Desc.(uKAD): ";
        os.write(reinterpret_cast<const char *>(kd->descriptor),
                 ntohs(kd->length));
        os.put('\n');
        break;
      case scsi::kad_type::akad:
        os << std::setw(25) << "Volume Key Desc.(aKAD): ";
        os.write(reinterpret_cast<const char *>(kd->descriptor),
                 ntohs(kd->length));
        os.put('\n');
        break;
      }
    }
    if ((opt.flags & scsi::page_nbes::flags_rdmds_mask) ==
        scsi::page_nbes::flags_rdmds_mask) {
      os << std::left << std::setw(25) << " Protected from raw read\n";
    }
    break;
  default:
    os << "Unknown result '" << std::hex
       << static_cast<unsigned int>(encryption_status) << "'\n";
    break;
  }
  if (opt.algorithm_index != 0) {
    os << std::left << std::setw(25)
       << "Volume Algorithm:" << static_cast<unsigned int>(opt.algorithm_index)
       << "\n";
  }
}

static void showVolumeStatus(const std::string& tapeDrive)
{
  alignas(4) scsi::page_buffer buffer;
  scsi::get_nbes(tapeDrive, buffer, sizeof(buffer));
  auto& opt {reinterpret_cast<const scsi::page_nbes&>(buffer)};

  print_volume_status(std::cout, opt);
}

static void echo(bool on)
{
  struct termios settings {};
  tcgetattr(STDIN_FILENO, &settings);
  settings.c_lflag =
      on ? (settings.c_lflag | ECHO) : (settings.c_lflag & ~(ECHO));
  tcsetattr(STDIN_FILENO, TCSANOW, &settings);
}

#if !defined(CATCH_CONFIG_MAIN)
int main(int argc, const char **argv)
{
  std::string tapeDrive;
  int action = 0; // 0 = status, 1 =setting param, 2 = generating key
  std::string keyFile, keyDesc;
  bool detail = false;

  scsi::encrypt_mode enc_mode;
  scsi::decrypt_mode dec_mode;
  std::uint8_t algorithm_index;
  std::vector<uint8_t> key;
  std::string key_name;
  scsi::sde_rdmc rdmc {};
  bool ckod {};

  // First load all of the options
  for (int i = 1; i < argc; i++) {
    std::string thisCmd = argv[i];
    std::string nextCmd = "";
    if (i + 1 < argc) {
      if (strncmp(argv[i + 1], "-", 1) != 0)
        nextCmd = argv[i + 1];
    }
    if (thisCmd == "--version") {
      std::cout << "stenc v" << VERSION << " - SCSI Tape Encryption Manager\n";
      std::cout << "https://github.com/scsitape/stenc \n";
      exit(EXIT_SUCCESS);
    }
    if (thisCmd == "-e") {
      if (nextCmd == "") {
        errorOut("Key file not specified after -k option");
      }
      if (nextCmd == "on") {
        // encrypt, read only encrypted data
        enc_mode = scsi::encrypt_mode::on;
        dec_mode = scsi::decrypt_mode::on;
      } else if (nextCmd == "mixed") {
        // encrypt, read encrypted and unencrypted data
        enc_mode = scsi::encrypt_mode::on;
        dec_mode = scsi::decrypt_mode::mixed;
      } else if (nextCmd == "rawread") {
        // encrypt, read encrypted and unencrypted data
        enc_mode = scsi::encrypt_mode::on;
        dec_mode = scsi::decrypt_mode::raw;
      } else if (nextCmd == "off") {
        // encrypt, read encrypted and unencrypted data
        enc_mode = scsi::encrypt_mode::off;
        dec_mode = scsi::decrypt_mode::off;
      } else {
        errorOut("Unknown encryption mode '" + nextCmd +
                 "'"); // encrypt, read encrypted and unencrypted data
      }
      i++; // skip the next argument
      action = 1;
    } else if (thisCmd == "-f") {
      if (nextCmd == "")
        errorOut("Device not specified after -f option.");
      tapeDrive = nextCmd; // set the tape drive
      i++;                 // skip the next argument
    } else if (thisCmd == "-k") {
      if (nextCmd == "")
        errorOut("Key file not specified after -k option");
      keyFile = nextCmd; // set the key file
      i++;               // skip the next argument
    } else if (thisCmd == "-kd") {
      if (nextCmd == "")
        errorOut("Key description not specified after the -kd option");
      keyDesc = nextCmd; // set the key file
      if (keyDesc.size() > SSP_UKAD_LENGTH) {
        errorOut("Key description too long!");
      }
      i++; // skip the next argument
    } else if (thisCmd == "--protect") {
      if (rdmc == scsi::sde_rdmc::enabled) {
        errorOut("'--protect' cannot be specified at the same time as "
                 "'--unprotect'");
      }
      rdmc = scsi::sde_rdmc::disabled;
    } else if (thisCmd == "--unprotect") {
      if (rdmc == scsi::sde_rdmc::disabled) {
        errorOut("'--unprotect' cannot be specified at the same time as "
                 "'--protect'");
      }
      rdmc = scsi::sde_rdmc::enabled;
    } else if (thisCmd == "--ckod") {
      ckod = true;
    } else if (thisCmd == "--detail") {
      detail = true;
    } else if (thisCmd == "-a") {
      if (nextCmd == "")
        errorOut("You must specify a numeric algorithm index when using the -a "
                 "flag");
      algorithm_index = std::atoi(nextCmd.c_str());
      i++; // skip the next argument
    } else {
      errorOut("Unknown command '" + thisCmd + "'");
    }
  }

  // select device from env variable or system default if not given with -f
  if (tapeDrive.empty()) {
    const char *env_tape = getenv("TAPE");
    if (env_tape != nullptr) {
      tapeDrive = env_tape;
    } else {
      tapeDrive = DEFTAPE;
    }
  }
  if (dec_mode == scsi::decrypt_mode::raw && rdmc == scsi::sde_rdmc::disabled) {
    errorOut(
        "'--protect' is not valid when setting encryption mode to 'rawread'");
  }

  openlog("stenc", LOG_CONS, LOG_USER);

  if (action == 0) {
    std::cout << "Status for " << tapeDrive << "\n"
              << "--------------------------------------------------\n";

    try {
      if (detail) {
        inquiryDrive(tapeDrive);
      }
      showDriveStatus(tapeDrive, detail);
      if (detail && scsi::is_device_ready(tapeDrive)) {
        try {
          showVolumeStatus(tapeDrive);
        } catch (const scsi::scsi_error& err) {
          // #71: ignore BLANK CHECK sense key that some drives may return
          // during media access check in getting NBES
          auto sense_key {err.get_sense().flags &
                          scsi::sense_data::flags_sense_key_mask};
          if (sense_key != scsi::sense_data::blank_check) {
            throw;
          }
        }
      }
      if (detail) {
        alignas(4) scsi::page_buffer buffer {};
        scsi::get_dec(tapeDrive, buffer, sizeof(buffer));
        auto& page {reinterpret_cast<const scsi::page_dec&>(buffer)};

        print_algorithms(std::cout, page);
      }
      exit(EXIT_SUCCESS);
    } catch (const scsi::scsi_error& err) {
      scsi::print_sense_data(std::cerr, err.get_sense());
      exit(EXIT_FAILURE);
    } catch (const std::runtime_error& err) {
      std::cerr << err.what() << '\n';
      exit(EXIT_FAILURE);
    }
  }

  if (enc_mode == scsi::encrypt_mode::on) {
    if (keyFile.empty()) {
      std::string p1;
      std::string p2;
      bool done = false;
      while (!done) {
        std::cout << "Enter key in hex format: ";
        echo(false);
        getline(std::cin, p1);
        echo(true);
        std::cout << "\nRe-enter key in hex format: ";
        echo(false);
        getline(std::cin, p2);
        echo(true);
        std::cout << "\n";
        if (p1 != p2) {
          std::cout << "Keys do not match!\n";
        } else if (p1.empty()) {
          std::cout << "Key cannot be empty!\n";
        } else {
          if (auto key_bytes = key_from_hex_chars(p1)) {
            std::cout << "Set encryption using this key? [y/n]: ";
            std::string ans = "";
            getline(std::cin, ans);
            if (ans == "y") {
              key = *key_bytes;
              done = true;
            }
          } else {
            std::cout << "Invalid key!\n";
          }
        }
      }
      key_name = keyDesc;
    } else {
      // set keyInput here
      std::string keyInput;
      std::ifstream myfile(keyFile.c_str());
      if (myfile.is_open()) {
        getline(myfile, keyInput);
        getline(myfile, keyDesc);
        myfile.close();
        if (auto key_bytes = key_from_hex_chars(keyInput)) {
          key = *key_bytes;
        } else {
          errorOut("Invalid key found in '" + keyFile + "'");
        }
        key_name = keyDesc;
      } else
        errorOut("Could not open '" + keyFile + "' for reading");
    }
  }

  // Write the options to the tape device
  std::cout << "Turning "
            << (enc_mode != scsi::encrypt_mode::off ? "on" : "off")
            << " encryption on device '" << tapeDrive << "'..." << std::endl;
  try {
    auto sde_buffer {scsi::make_sde(enc_mode, dec_mode, algorithm_index, key,
                                    key_name, rdmc, ckod)};
    scsi::write_sde(tapeDrive, sde_buffer.get());

    alignas(4) scsi::page_buffer buffer {};
    scsi::get_des(tapeDrive, buffer, sizeof(buffer));
    auto& opt {reinterpret_cast<const scsi::page_des&>(buffer)};

    if (enc_mode != scsi::encrypt_mode::off &&
        opt.encryption_mode == scsi::encrypt_mode::off) {
      errorOut("Turning encryption on for '" + tapeDrive + "' failed!");
    }
    if (enc_mode == scsi::encrypt_mode::off &&
        opt.encryption_mode != scsi::encrypt_mode::off) {
      errorOut("Turning encryption off for '" + tapeDrive + "' failed!");
    }

    if (enc_mode != scsi::encrypt_mode::off) {
      std::stringstream msg;
      msg << "Encryption turned on for device '" << tapeDrive << "'. ";
      if (!key_name.empty()) {
        msg << "Key Descriptor: '" << key_name << "'";
      }
      msg << " Key Instance: " << std::dec << ntohl(opt.key_instance_counter)
          << std::endl;

      syslog(LOG_NOTICE, "%s", msg.str().c_str());
    } else {
      std::stringstream msg {};

      msg << "Encryption turned off for device '" << tapeDrive << "'.";
      msg << " Key Instance: " << std::dec << ntohl(opt.key_instance_counter)
          << std::endl;

      syslog(LOG_NOTICE, "%s", msg.str().c_str());
    }
    std::cout << "Success! See system logs for a key change audit log.\n";
    exit(EXIT_SUCCESS);
  } catch (const scsi::scsi_error& err) {
    scsi::print_sense_data(std::cerr, err.get_sense());
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << '\n';
  }

  if (enc_mode != scsi::encrypt_mode::off) {
    errorOut("Turning encryption on for '" + tapeDrive + "' failed!");
  } else {
    errorOut("Turning encryption off for '" + tapeDrive + "' failed!");
  }
}
#endif // defined(CATCH_CONFIG_MAIN)
