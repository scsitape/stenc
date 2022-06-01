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

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <getopt.h>
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

using namespace std::literals::string_literals;

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
static void print_usage(std::ostream& os)
{
  os << "\
Usage: stenc [OPTION...]\n\
\n\
Mandatory arguments to long options are mandatory for short options too.\n\
  -f, --file=DEVICE        use DEVICE as the tape drive to operate on\n\
  -e, --encrypt=ENC-MODE   set encryption mode to ENC-MODE\n\
  -d, --decrypt=DEC-MODE   set decryption mode to DEC-MODE\n\
  -k, --key-file=FILE      read encryption key and key descriptor from FILE,\n\
                           or standard input when FILE is -\n\
  -a, --algorithm=INDEX    use encryption algorithm INDEX\n\
      --allow-raw-read     mark written blocks to allow raw reads of\n\
                           encrypted data\n\
      --no-allow-raw-read  mark written blocks to disallow raw reads of\n\
                           encrypted data\n\
      --ckod               clear key on demount of tape media\n\
  -h, --help               print this usage statement and exit\n\
      --version            print version information and exit\n\
\n\
ENC-MODE is one of the following:\n\
  off    Data written to DEVICE will not be encrypted\n\
  on     Data written to DEVICE will be encrypted\n\
\n\
DEC-MODE is one of the following:\n\
  off    Data read from DEVICE will not be decrypted and only unencrypted\n\
         records can be read.\n\
  on     Data read from DEVICE will be decrypted and only encrypted records\n\
         can be read.\n\
  mixed  Data read from DEVICE will be decrypted, if needed. Both encrypted\n\
         and unencrypted records can be read.\n\
\n\
INDEX is a number that selects the encryption algorithm and mode to use.\n\
\n\
When neither options to set encryption or decryption mode are given, print\n\
encryption status and capabilities of DEVICE, including a list of supported\n\
algorithm indexes.\n";
}

static void print_algorithm_name(std::ostream& os, const std::uint32_t code)
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

  for (const scsi::algorithm_descriptor& ad: algorithms) {
    os << std::left << std::setw(5)
       << static_cast<unsigned int>(ad.algorithm_index);
    print_algorithm_name(os, ntohl(ad.security_algorithm_code));
    os.put('\n');

    // Print KAD capabilities and size
    auto dkad_c {static_cast<unsigned int>(
        ad.flags3 & scsi::algorithm_descriptor::flags3_dkad_c_mask)};
    if (dkad_c == 2u << scsi::algorithm_descriptor::flags3_dkad_c_pos) {
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

static void print_device_status(std::ostream& os, const scsi::page_des& opt)
{
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
     << ntohl(opt.key_instance_counter) << '\n';
  if (opt.algorithm_index != 0) {
    os << std::setw(25) << "Encryption Algorithm:" << std::dec
       << static_cast<unsigned int>(opt.algorithm_index) << '\n';
  }
  auto kads {scsi::read_page_kads(opt)};
  for (const scsi::kad& kd: kads) {
    switch (kd.type) {
    case scsi::kad_type::ukad:
      os << std::setw(25) << "Drive Key Desc.(uKAD): ";
      os.write(reinterpret_cast<const char *>(kd.descriptor), ntohs(kd.length));
      os.put('\n');
      break;
    case scsi::kad_type::akad:
      os << std::setw(25) << "Drive Key Desc.(aKAD): ";
      os.write(reinterpret_cast<const char *>(kd.descriptor), ntohs(kd.length));
      os.put('\n');
      break;
    }
  }
}

static void print_volume_status(std::ostream& os, const scsi::page_nbes& opt)
{
  auto compression_status {static_cast<std::uint8_t>(
      opt.status & scsi::page_nbes::status_compression_mask)};
  // From vendor docs, no known drives actually report anything other than 0
  if (compression_status != 0u) {
    os << std::left << std::setw(25) << "Volume Compressed:";
    switch (compression_status) {
    case 0u << scsi::page_nbes::status_compression_pos:
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
      opt.status & scsi::page_nbes::status_encryption_mask)};
  auto kads {read_page_kads(opt)};
  switch (encryption_status) {
  case 0u << scsi::page_nbes::status_encryption_pos:
  case 1u << scsi::page_nbes::status_encryption_pos:
    os << "Unable to determine\n";
    break;
  case 2u << scsi::page_nbes::status_encryption_pos:
    os << "Tape position not at a logical block\n";
    break;
  case 3u << scsi::page_nbes::status_encryption_pos:
    os << "Not encrypted\n";
    break;
  case 5u << scsi::page_nbes::status_encryption_pos:
    os << "Encrypted and able to decrypt\n";
    if ((opt.flags & scsi::page_nbes::flags_rdmds_mask) ==
        scsi::page_nbes::flags_rdmds_mask) {
      os << std::left << std::setw(25) << " Protected from raw read\n";
    }
    break;
  case 6u << scsi::page_nbes::status_encryption_pos:
    os << "Encrypted, but unable to decrypt due to invalid key.\n";
    for (const scsi::kad& kd: kads) {
      switch (kd.type) {
      case scsi::kad_type::ukad:
        os << std::setw(25) << "Volume Key Desc.(uKAD): ";
        os.write(reinterpret_cast<const char *>(kd.descriptor),
                 ntohs(kd.length));
        os.put('\n');
        break;
      case scsi::kad_type::akad:
        os << std::setw(25) << "Volume Key Desc.(aKAD): ";
        os.write(reinterpret_cast<const char *>(kd.descriptor),
                 ntohs(kd.length));
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
       << '\n';
  }
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
int main(int argc, char **argv)
{
  std::string tapeDrive;
  std::string keyFile;

  std::optional<scsi::encrypt_mode> enc_mode;
  std::optional<scsi::decrypt_mode> dec_mode;
  std::optional<std::uint8_t> algorithm_index;
  std::vector<uint8_t> key;
  std::string key_name;
  scsi::sde_rdmc rdmc {};
  bool ckod {};

  alignas(4) scsi::page_buffer buffer {};

  enum opt_key : int {
    opt_version = 256,
    opt_ckod,
    opt_rdmc_enable,
    opt_rdmc_disable,
  };

  const struct option long_options[] = {
      {"algorithm", required_argument, nullptr, 'a'},
      {"decrypt", required_argument, nullptr, 'd'},
      {"encrypt", required_argument, nullptr, 'e'},
      {"file", required_argument, nullptr, 'f'},
      {"key-file", required_argument, nullptr, 'k'},
      {"help", no_argument, nullptr, 'h'},
      {"ckod", no_argument, nullptr, opt_ckod},
      {"allow-raw-read", no_argument, nullptr, opt_rdmc_enable},
      {"no-allow-raw-read", no_argument, nullptr, opt_rdmc_disable},
      {"version", no_argument, nullptr, opt_version},
      {nullptr, 0, nullptr, 0},
  };

  int opt_char;
  while ((opt_char = getopt_long(argc, argv, "+a:d:e:f:k:h", long_options,
                                 nullptr)) != -1) {
    switch (opt_char) {
    case 'a':
      algorithm_index = std::atoi(optarg);
      break;
    case 'd': {
      std::string arg {optarg};
      if (arg == "on"s) {
        dec_mode = scsi::decrypt_mode::on;
      } else if (arg == "off"s) {
        dec_mode = scsi::decrypt_mode::off;
      } else if (arg == "mixed"s) {
        dec_mode = scsi::decrypt_mode::mixed;
      } else {
        print_usage(std::cerr);
        std::exit(EXIT_FAILURE);
      }
      break;
    }
    case 'e': {
      std::string arg {optarg};
      if (arg == "on"s) {
        enc_mode = scsi::encrypt_mode::on;
      } else if (arg == "off"s) {
        enc_mode = scsi::encrypt_mode::off;
      } else {
        print_usage(std::cerr);
        std::exit(EXIT_FAILURE);
      }
      break;
    }
    case 'f':
      tapeDrive = optarg;
      break;
    case 'k':
      keyFile = optarg;
      break;
    case opt_ckod:
      ckod = true;
      break;
    case opt_rdmc_enable:
      rdmc = scsi::sde_rdmc::enabled;
      break;
    case opt_rdmc_disable:
      rdmc = scsi::sde_rdmc::disabled;
      break;
    case 'h':
      print_usage(std::cout);
      std::exit(EXIT_SUCCESS);
    case opt_version:
      std::cout << "stenc " VERSION " - SCSI Tape Encryption Manager\n"
                << "https://github.com/scsitape/stenc\n";
      std::exit(EXIT_SUCCESS);
    default:
      print_usage(std::cerr);
      std::exit(EXIT_FAILURE);
    }
  }
  if (optind != argc) { // left-over unparsed arguments or options
    print_usage(std::cerr);
    std::exit(EXIT_FAILURE);
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

  openlog("stenc", LOG_CONS, LOG_USER);

  if (!enc_mode && !dec_mode) {
    std::cout << "Status for " << tapeDrive << '\n'
              << "--------------------------------------------------\n";

    try {
      print_device_inquiry(std::cout, scsi::get_inquiry(tapeDrive));
      scsi::get_des(tapeDrive, buffer, sizeof(buffer));
      print_device_status(std::cout,
                          reinterpret_cast<const scsi::page_des&>(buffer));
      if (scsi::is_device_ready(tapeDrive)) {
        try {
          scsi::get_nbes(tapeDrive, buffer, sizeof(buffer));
          print_volume_status(std::cout,
                              reinterpret_cast<const scsi::page_nbes&>(buffer));
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
      scsi::get_dec(tapeDrive, buffer, sizeof(buffer));
      print_algorithms(std::cout,
                       reinterpret_cast<const scsi::page_dec&>(buffer));
      std::exit(EXIT_SUCCESS);
    } catch (const scsi::scsi_error& err) {
      std::cerr << "stenc: " << err.what() << '\n';
      scsi::print_sense_data(std::cerr, err.get_sense());
      std::exit(EXIT_FAILURE);
    } catch (const std::runtime_error& err) {
      std::cerr << "stenc: " << err.what() << '\n';
      std::exit(EXIT_FAILURE);
    }
  }

  // Infer encrypt/decrypt mode when only one is specified
  if (enc_mode && !dec_mode) {
    if (enc_mode == scsi::encrypt_mode::off) {
      dec_mode = scsi::decrypt_mode::off;
      std::cerr << "Decrypt mode not specified, using decrypt = off\n";
    } else if (enc_mode == scsi::encrypt_mode::on) {
      dec_mode = scsi::decrypt_mode::on;
      std::cerr << "Decrypt mode not specified, using decrypt = on\n";
    } else {
      std::cerr << "stenc: Unexpected encrypt mode "
                << static_cast<unsigned int>(*enc_mode) << '\n';
      std::exit(EXIT_FAILURE);
    }
  } else if (!enc_mode && dec_mode) {
    if (dec_mode == scsi::decrypt_mode::off) {
      enc_mode = scsi::encrypt_mode::off;
      std::cerr << "Encrypt mode not specified, using encrypt = off\n";
    } else if (dec_mode == scsi::decrypt_mode::on ||
               dec_mode == scsi::decrypt_mode::mixed) {
      enc_mode = scsi::encrypt_mode::on;
      std::cerr << "Encrypt mode not specified, using encrypt = on\n";
    } else {
      std::cerr << "stenc: Unexpected decrypt mode "
                << static_cast<unsigned int>(*dec_mode) << '\n';
      std::exit(EXIT_FAILURE);
    }
  }

  if (enc_mode != scsi::encrypt_mode::off ||
      dec_mode != scsi::decrypt_mode::off) {
    if (keyFile.empty()) {
      std::cerr << "stenc: Encryption key required but no key file specified\n";
      std::exit(EXIT_FAILURE);
    }

    // set keyInput here
    std::string keyInput;

    if (keyFile == "-"s) { // Read key file from standard input
      if (isatty(STDIN_FILENO)) {
        std::cout << "Enter key in hex format (input will be hidden): ";
        echo(false);
      }
      std::getline(std::cin, keyInput);
      if (isatty(STDIN_FILENO)) {
        std::cout << "\nEnter key descriptor (optional): ";
        echo(true);
      }
      std::getline(std::cin, key_name);
    } else {
      std::ifstream myfile {keyFile};
      if (!myfile.is_open()) {
        std::cerr << "stenc: Cannot open " << keyFile << ": " << strerror(errno)
                  << '\n';
        std::exit(EXIT_FAILURE);
      }
      std::getline(myfile, keyInput);
      std::getline(myfile, key_name);
    }

    if (auto key_bytes = key_from_hex_chars(keyInput)) {
      key = *key_bytes;
    } else {
      std::cerr << "stenc: Invalid key in key file\n";
      std::exit(EXIT_FAILURE);
    }
  }

  try {
    scsi::get_dec(tapeDrive, buffer, sizeof(buffer));
    auto& dec_page {reinterpret_cast<const scsi::page_dec&>(buffer)};
    auto algorithms {scsi::read_algorithms(dec_page)};

    if (algorithm_index == std::nullopt) {
      if (algorithms.size() == 1) {
        // Pick the only available algorithm if not specified
        const scsi::algorithm_descriptor& ad = algorithms[0];
        std::cerr << "Algorithm index not specified, using " << std::dec
                  << static_cast<unsigned int>(ad.algorithm_index) << " (";
        print_algorithm_name(std::cerr, ntohl(ad.security_algorithm_code));
        std::cerr << ")\n";
        algorithm_index = ad.algorithm_index;
      } else {
        std::cerr << "stenc: Algorithm index not specified\n";
        print_algorithms(std::cerr, dec_page);
        std::exit(EXIT_FAILURE);
      }
    }

    auto algo_it {
        std::find_if(algorithms.begin(), algorithms.end(),
                     [algorithm_index](const scsi::algorithm_descriptor& ad) {
                       return ad.algorithm_index == algorithm_index;
                     })};
    if (algo_it == algorithms.end()) {
      std::cerr << "stenc: Algorithm index " << std::dec
                << static_cast<unsigned int>(*algorithm_index)
                << " not supported by device\n";
      std::exit(EXIT_FAILURE);
    }
    const scsi::algorithm_descriptor& ad = *algo_it;

    if ((enc_mode != scsi::encrypt_mode::off ||
         dec_mode != scsi::decrypt_mode::off) &&
        key.size() != ntohs(ad.key_length)) {
      std::cerr << "stenc: Incorrect key size, expected " << std::dec
                << ntohs(ad.key_length) << " bytes, got " << key.size() << '\n';
      std::exit(EXIT_FAILURE);
    }

    if (key_name.size() > ntohs(ad.maximum_ukad_length)) {
      std::cerr << "stenc: Key descriptor exceeds maximum length " << std::dec
                << ntohs(ad.maximum_ukad_length) << '\n';
      std::exit(EXIT_FAILURE);
    }

    bool ukad_fixed =
        (ad.flags2 & scsi::algorithm_descriptor::flags2_ukadf_mask) ==
        scsi::algorithm_descriptor::flags2_ukadf_mask;
    if (ukad_fixed && key_name.size() < ntohs(ad.maximum_ukad_length)) {
      // Pad key descriptor to required length
      key_name.resize(ntohs(ad.maximum_ukad_length), ' ');
    }

    if (enc_mode != scsi::encrypt_mode::on) {
      // key descriptor only valid when key is used for writing
      key_name.erase();
    }

    // Write the options to the tape device
    std::cerr << "Changing encryption settings for device " << tapeDrive
              << "...\n";
    auto sde_buffer {scsi::make_sde(enc_mode.value(), dec_mode.value(),
                                    algorithm_index.value(), key, key_name,
                                    rdmc, ckod)};
    scsi::write_sde(tapeDrive, sde_buffer.get());
    scsi::get_des(tapeDrive, buffer, sizeof(buffer));
    auto& opt {reinterpret_cast<const scsi::page_des&>(buffer)};
    std::ostringstream oss;

    oss << "Encryption settings changed for device " << tapeDrive
        << ": mode: encrypt = " << enc_mode.value()
        << ", decrypt = " << dec_mode.value() << '.';
    if (!key_name.empty()) {
      oss << " Key Descriptor: '" << key_name << "',";
    }
    oss << " Key Instance Counter: " << std::dec
        << ntohl(opt.key_instance_counter) << '\n';
    syslog(LOG_NOTICE, "%s", oss.str().c_str());
    std::cerr << "Success! See system logs for a key change audit log.\n";
  } catch (const scsi::scsi_error& err) {
    std::cerr << "stenc: " << err.what() << '\n';
    scsi::print_sense_data(std::cerr, err.get_sense());
    std::exit(EXIT_FAILURE);
  } catch (const std::runtime_error& err) {
    std::cerr << "stenc: " << err.what() << '\n';
    std::exit(EXIT_FAILURE);
  }
}
#endif // defined(CATCH_CONFIG_MAIN)
