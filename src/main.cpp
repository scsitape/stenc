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

#include <syslog.h>
#include <sys/mtio.h>
#include <sys/stat.h>
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

typedef struct {
#if STENC_BIG_ENDIAN == 0
  unsigned char bit1 : 1;
  unsigned char bit2 : 1;
  unsigned char bit3 : 1;
  unsigned char bit4 : 1;
  unsigned char bit5 : 1;
  unsigned char bit6 : 1;
  unsigned char bit7 : 1;
  unsigned char bit8 : 1;
#else
  unsigned char bit8 : 1;
  unsigned char bit7 : 1;
  unsigned char bit6 : 1;
  unsigned char bit5 : 1;
  unsigned char bit4 : 1;
  unsigned char bit3 : 1;
  unsigned char bit2 : 1;
  unsigned char bit1 : 1;
#endif
} bitcheck;

void showUsage();
void errorOut(const std::string& message);
void inquiryDrive(const std::string& tapeDevice);
void showDriveStatus(const std::string& tapeDevice, bool detail);
void showVolumeStatus(const std::string& tapeDevice);
void echo(bool);

static std::optional<std::vector<uint8_t>> key_from_hex_chars(const std::string& s)
{
  auto it = s.data();
  std::vector<uint8_t> bytes;

  if (s.size() % 2) {  // treated as if there is an implicit leading 0
    uint8_t result;
    auto [ptr, ec] { std::from_chars(it, it + 1, result, 16) };
    if (ec != std::errc {}) {
      return {};
    }
    bytes.push_back(result);
    it = ptr;
  }

  while (*it) {
    uint8_t result;
    auto [ptr, ec] { std::from_chars(it, it + 2, result, 16) };
    if (ec != std::errc {}) {
      return {};
    }
    bytes.push_back(result);
    it = ptr;
  }
  return bytes;
}

#if !defined(CATCH_CONFIG_MAIN)
int main(int argc, const char **argv) {
  bitcheck bc;
  memset(&bc, 0, 1);
  bc.bit2 = 1;
  bc.bit5 = 1;
  unsigned char check;
  memcpy(&check, &bc, 1);

  switch ((int)check) {
  case 0x12:
    // this is good
    break;
  case 0x48:
#if STENC_BIG_ENDIAN == 1
    errorOut("Swapped bit ordering detected(BI).  Program needs to be "
             "configured without the --enable-swapendian option in order to "
             "function properly on your system");
#else
    errorOut("Swapped bit ordering detected(LI).  Program needs to be "
             "configured with the --enable-swapendian option in order to "
             "function properly on your system");
#endif
    break;
  default:
    std::cerr << "Unknown bit check result " << std::hex << check << "\n";
    errorOut("Exiting program because it will not run properly");
    break;
  }

  std::string tapeDrive;
  int action = 0; // 0 = status, 1 =setting param, 2 = generating key
  std::string keyFile, keyDesc;
  int keyLength = 0;
  bool detail = false;
  SCSIEncryptOptions drvOptions;

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
      if (nextCmd == "")
        errorOut("Key file not specified after -k option");
      if (nextCmd == "on")
        drvOptions.cryptMode = CRYPTMODE_ON; // encrypt, read only encrypted
                                             // data
      else if (nextCmd == "mixed")
        drvOptions.cryptMode =
            CRYPTMODE_MIXED; // encrypt, read encrypted and unencrypted data
      else if (nextCmd == "rawread")
        drvOptions.cryptMode =
            CRYPTMODE_RAWREAD; // encrypt, read encrypted and unencrypted data
      else if (nextCmd == "off")
        drvOptions.cryptMode =
            CRYPTMODE_OFF; // encrypt, read encrypted and unencrypted data
      else
        errorOut("Unknown encryption mode '" + nextCmd +
                 "'"); // encrypt, read encrypted and unencrypted data
      i++;             // skip the next argument
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
      if (drvOptions.rdmc == RDMC_UNPROTECT)
        errorOut("'--protect' cannot be specified at the same time as "
                 "'--unprotect'");
      drvOptions.rdmc = RDMC_PROTECT;
    } else if (thisCmd == "--unprotect") {
      if (drvOptions.rdmc == RDMC_PROTECT)
        errorOut("'--unprotect' cannot be specified at the same time as "
                 "'--protect'");
      drvOptions.rdmc = RDMC_UNPROTECT;
    } else if (thisCmd == "--ckod") {
      drvOptions.CKOD = true;
    } else if (thisCmd == "--detail") {
      detail = true;
    } else if (thisCmd == "-a") {
      if (nextCmd == "")
        errorOut("You must specify a numeric algorithm index when using the -a "
                 "flag");
      drvOptions.algorithmIndex = std::atoi(nextCmd.c_str());
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
  if (drvOptions.cryptMode == CRYPTMODE_RAWREAD &&
      drvOptions.rdmc == RDMC_PROTECT) {
    errorOut(
        "'--protect' is not valid when setting encryption mode to 'rawread'");
  }

  openlog("stenc", LOG_CONS, LOG_USER);

  if (action == 0) {
    std::cout << "Status for " << tapeDrive << "\n"
    << "--------------------------------------------------\n";

    try {
      if (detail){
        inquiryDrive(tapeDrive);
      }
      showDriveStatus(tapeDrive, detail);
      if (detail){
        showVolumeStatus(tapeDrive);
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

  if (drvOptions.cryptMode != CRYPTMODE_OFF) {
    if (keyFile == "") {
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
              drvOptions.cryptoKey = *key_bytes;
              done = true;
            }
          } else {
            std::cout << "Invalid key!\n";
          }
        }
      }
      drvOptions.keyName = keyDesc;

    } else {
      // set keyInput here
      std::string keyInput;
      std::ifstream myfile(keyFile.c_str());
      if (myfile.is_open()) {
        getline(myfile, keyInput);
        getline(myfile, keyDesc);
        myfile.close();
        if (auto key_bytes = key_from_hex_chars(keyInput)) {
          drvOptions.cryptoKey = *key_bytes;
        } else {
          errorOut("Invalid key found in '" + keyFile + "'");
        }
        drvOptions.keyName = keyDesc;
      } else
        errorOut("Could not open '" + keyFile + "' for reading");
    }
  }

  // Write the options to the tape device
  std::cout << "Turning "
            << ((drvOptions.cryptMode != CRYPTMODE_OFF) ? "on" : "off")
            << " encryption on device '" << tapeDrive << "'..." << std::endl;
  bool res = SCSIWriteEncryptOptions(tapeDrive, &drvOptions);
  if (res) {

    SSP_DES *opt = SSPGetDES(tapeDrive);
    if (drvOptions.cryptMode != CRYPTMODE_OFF && opt->des.encryptionMode != 2) {
      errorOut("Turning encryption on for '" + tapeDrive + "' failed!");
    }
    if (drvOptions.cryptMode == CRYPTMODE_OFF && opt->des.encryptionMode != 0) {
      errorOut("Turning encryption off for '" + tapeDrive + "' failed!");
    }
    delete opt;

    if (drvOptions.cryptMode != CRYPTMODE_OFF) {
      std::stringstream msg;
      msg << "Encryption turned on for device '" << tapeDrive << "'. ";
      if (!drvOptions.keyName.empty()) {
        msg << "Key Descriptor: '" << drvOptions.keyName << "'";
      }
      msg << " Key Instance: " << std::dec << BSLONG(opt->des.keyInstance)
          << std::endl;

      syslog(LOG_NOTICE, "%s", msg.str().c_str());
    } else {
      std::stringstream msg{};

      msg << "Encryption turned off for device '" << tapeDrive << "'.";
      msg << " Key Instance: " << std::dec << BSLONG(opt->des.keyInstance)
          << std::endl;

      syslog(LOG_NOTICE, "%s", msg.str().c_str());
    }
    std::cout << "Success! See system logs for a key change audit log.\n";
    exit(EXIT_SUCCESS);
  }
  if (drvOptions.cryptMode != CRYPTMODE_OFF) {
    errorOut("Turning encryption on for '" + tapeDrive + "' failed!");
  } else {
    errorOut("Turning encryption off for '" + tapeDrive + "' failed!");
  }
}
#endif // defined(CATCH_CONFIG_MAIN)

// exits to shell with an error message
void errorOut(const std::string& message) {
  std::cerr << "Error: " << message << "\n";
  showUsage();
  exit(EXIT_FAILURE);
}

// shows the command usage
void showUsage() {
  std::cerr
      << "Usage: stenc --version | "
         "-f <device> [--detail] [-e <on/mixed/rawread/off> [-k <file>] "
         "[-kd <description>] [-a <index>] [--protect | --unprotect] [--ckod] ]\n\n"
         "Type 'man stenc' for more information.\n";
}

static void print_device_inquiry(std::ostream& os, const scsi::inquiry_data& iresult)
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

void inquiryDrive(const std::string& tapeDevice) {
  // todo: std::cout should not be used outside main()
  auto iresult {scsi::get_inquiry(tapeDevice)};
  print_device_inquiry(std::cout, iresult);
}

static void print_device_status(std::ostream& os, const scsi::page_des& opt, bool detail)
{
  std::string emode = "unknown";
  os << std::left << std::setw(25) << "Drive Encryption:";
  if (opt.encryption_mode == scsi::encrypt_mode::on && // encrypt
      opt.decryption_mode == scsi::decrypt_mode::on    // read only encrypted data
  )
    emode = "on";
  if (opt.encryption_mode == scsi::encrypt_mode::on && // encrypt
      opt.decryption_mode == scsi::decrypt_mode::mixed // read encrypted and unencrypted
  )
    emode = "mixed";

  if (opt.encryption_mode == scsi::encrypt_mode::on && // encrypt
      opt.decryption_mode == scsi::decrypt_mode::raw   // read encrypted and unencrypted
  )
    emode = "rawread";

  if (opt.encryption_mode == scsi::encrypt_mode::off && // encrypt
      opt.decryption_mode == scsi::decrypt_mode::off    // read encrypted and unencrypted
  )
    emode = "off";

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
      os << "Unknown '0x" << std::hex << static_cast<unsigned int>(opt.decryption_mode)
         << "' \n";
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
    if ((opt.flags & scsi::page_des::flags_rdmd_mask) == scsi::page_des::flags_rdmd_mask) {
      os << std::setw(25) << " "
         << "Protecting from raw read\n";
    }

    os << std::setw(25) << "Key Instance Counter:" << std::dec
       << ntohl(opt.key_instance_counter) << "\n";
    if (opt.algorithm_index != 0) {
      os << std::setw(25) << "Encryption Algorithm:" << std::hex
         << static_cast<unsigned int>(opt.algorithm_index) << "\n";
    }
  }
  auto kads {scsi::read_page_kads(opt)};
  for (auto kd: kads) {
    switch (kd->type) {
    case KAD_TYPE_UKAD:
      os << std::setw(25) << "Drive Key Desc.(uKAD): ";
      os.write(reinterpret_cast<const char *>(kd->descriptor), ntohs(kd->length));
      os.put('\n');
      break;
    case KAD_TYPE_AKAD:
      os << std::setw(25) << "Drive Key Desc.(aKAD): ";
      os.write(reinterpret_cast<const char *>(kd->descriptor), ntohs(kd->length));
      os.put('\n');
      break;
    }
  }
}

void showDriveStatus(const std::string& tapeDrive, bool detail) {
  alignas(4) scsi::page_buffer buffer;
  scsi::get_des(tapeDrive, buffer, sizeof(buffer));
  auto& opt {reinterpret_cast<const scsi::page_des&>(buffer)};

  print_device_status(std::cout, opt, detail);
}

static void print_volume_status(std::ostream& os, const scsi::page_nbes& opt)
{
  auto compression_status {
    static_cast<std::uint8_t>((opt.status & scsi::page_nbes::status_compression_mask)
                              >> scsi::page_nbes::status_compression_pos)
  };
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
  auto encryption_status {
    static_cast<std::uint8_t>((opt.status & scsi::page_nbes::status_encryption_mask)
                              >> scsi::page_nbes::status_encryption_pos)
  };
  auto kads {read_page_kads(opt)};
  switch (encryption_status) {
  case 1u:
    os << "Unable to determine\n";
    break;
  case 2u:
    os << "Logical block is not a logical block\n";
    break;
  case 3u:
    os << "Not encrypted\n";
    break;
  case 5u:
    os << "Encrypted and able to decrypt\n";
    if ((opt.flags & scsi::page_nbes::flags_rdmds_mask) == scsi::page_nbes::flags_rdmds_mask) {
      os << std::left << std::setw(25) << " Protected from raw read\n";
    }
    break;
  case 6u:
    os << "Encrypted, but unable to decrypt due to invalid key.\n";
    for (auto kd: kads) {
      switch (kd->type) {
      case KAD_TYPE_UKAD:
        os << std::setw(25) << "Volume Key Desc.(uKAD): ";
        os.write(reinterpret_cast<const char *>(kd->descriptor), ntohs(kd->length));
        os.put('\n');
        break;
      case KAD_TYPE_AKAD:
        os << std::setw(25) << "Volume Key Desc.(aKAD): ";
        os.write(reinterpret_cast<const char *>(kd->descriptor), ntohs(kd->length));
        os.put('\n');
        break;
      }
    }
    if ((opt.flags & scsi::page_nbes::flags_rdmds_mask) == scsi::page_nbes::flags_rdmds_mask) {
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
       << "Volume Algorithm:" << static_cast<unsigned int>(opt.algorithm_index) << "\n";
  }
}

void showVolumeStatus(const std::string& tapeDrive) {
  alignas(4) scsi::page_buffer buffer;
  scsi::get_nbes(tapeDrive, buffer, sizeof(buffer));
  auto& opt {reinterpret_cast<const scsi::page_nbes&>(buffer)};

  print_volume_status(std::cout, opt);
}

void echo(bool on) {
  struct termios settings {};
  tcgetattr(STDIN_FILENO, &settings);
  settings.c_lflag =
      on ? (settings.c_lflag | ECHO) : (settings.c_lflag & ~(ECHO));
  tcsetattr(STDIN_FILENO, TCSANOW, &settings);
}
