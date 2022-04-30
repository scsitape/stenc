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
#include "scsiencrypt.h"

#include <charconv>
#include <config.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <optional>
#include <stdint.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <vector>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <ostream>

#define LOGFILE "/var/log/stenc"

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

using namespace std;
void showUsage();
void errorOut(std::string const message);
void inquiryDrive(std::string tapeDevice);
void showDriveStatus(std::string tapeDevice, bool detail);
void showVolumeStatus(std::string tapeDevice);
std::string randomKey(int length);
std::string timestamp();
void echo(bool);
std::ofstream logFile;

static std::optional<std::vector<uint8_t>> key_from_hex_chars(const std::string& s)
{
  auto it = s.data();
  std::vector<uint8_t> bytes;

  if (s.size() % 2) {  // treated as if there is an implicit leading 0
    uint8_t result;
    auto [ptr, ec] { std::from_chars(it, it + 1, result, 16) };
    if (ec != errc {}) {
      return {};
    }
    bytes.push_back(result);
    it = ptr;
  }

  while (*it) {
    uint8_t result;
    auto [ptr, ec] { std::from_chars(it, it + 2, result, 16) };
    if (ec != errc {}) {
      return {};
    }
    bytes.push_back(result);
    it = ptr;
  }
  return bytes;
}

int main(int argc, char **argv) {
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

  std::string tapeDrive = "";
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
    if (thisCmd == "-g") { // Check if the help flag was passed.  If it was,
                           // show usage and exit
      if (nextCmd == "")
        errorOut("Key size must be specified when using -g");
      i++; // skip the next argument
      keyLength = std::atoi(nextCmd.c_str());
      if (keyLength % 8 != 0)
        errorOut("Key size must be divisible by 8");
      keyLength = keyLength / 8;
      if (keyLength > SSP_KEY_LENGTH) {
        std::cout << "Warning: Keys over " << (SSP_KEY_LENGTH * 8)
                  << " bits cannot be used by this program! \n";
      }
      action = 2; // generating key
    } else if (thisCmd == "-e") {
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

  if (action == 2) { // generate key
    if (keyFile == "") {
      errorOut("Specify file to save into with the -k argument.");
    }

    std::string const newkey = randomKey(keyLength);
    std::ofstream kf{};
    umask(077); // make sure that no one else can read the new key file
    kf.open(keyFile.c_str(), std::ios::trunc);
    if (!kf.is_open()) {
      errorOut("Could not open '" + keyFile + "' for writing.");
    }
    kf << newkey << keyDesc;
    kf.close();
    std::cout << "Random key saved into '" << keyFile << "'\n";
    chmod(keyFile.c_str(), 0600);
    std::cout << "Permissions of keyfile set to 600\n";
    exit(EXIT_SUCCESS);
  }
  // validate the tape device
  if (tapeDrive == "") {
    errorOut("Tape drive device must be specified with the -f option");
  }
  if (drvOptions.cryptMode == CRYPTMODE_RAWREAD &&
      drvOptions.rdmc == RDMC_PROTECT) {
    errorOut(
        "'--protect' is not valid when setting encryption mode to 'rawread'");
  }

#ifndef DISABLE_DEVICE_NAME_CONVERSION
  if (tapeDrive.find(".") == std::string::npos) {
    if (tapeDrive.substr(0, 7) == "/dev/st") {
      tapeDrive = "/dev/nst" + tapeDrive.substr(7, tapeDrive.size() - 6);
    }

    if (tapeDrive.substr(0, 8) == "/dev/rmt" &&
        tapeDrive.substr(tapeDrive.size() - 2, 2) != ".1") {
      tapeDrive = "/dev/rmt" + tapeDrive.substr(8, tapeDrive.size() - 7) + ".1";
    }
  }
#endif
  if (getuid() != 0) {
    errorOut("You must be root to read or set encryption options on a drive!");
  }
  logFile.open(LOGFILE, std::ios::app);
  if (!logFile.is_open()) {
    std::cout << "Warning: Could not open '" << LOGFILE
              << "' for key change auditing!\n";
  }
  chmod(LOGFILE, 0600);

  if (action == 0) {
    std::cout << "Status for " << tapeDrive << "\n"
    << "--------------------------------------------------\n";

    if (detail)
      inquiryDrive(tapeDrive);
    showDriveStatus(tapeDrive, detail);
    if (detail)
      showVolumeStatus(tapeDrive);
    exit(EXIT_SUCCESS);
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

      if (logFile.is_open()) {
        logFile << timestamp() << ": " << msg.str();
      }
    } else {
      std::stringstream msg{};

      msg << "Encryption turned off for device '" << tapeDrive << "'.";
      msg << " Key Instance: " << std::dec << BSLONG(opt->des.keyInstance)
          << std::endl;

      if (logFile.is_open())
        logFile << timestamp() << ": " << msg.str();
    }
    std::cout << "Success! See '" << LOGFILE << "' for a key change audit log."
              << std::endl;
    exit(EXIT_SUCCESS);
  }
  if (drvOptions.cryptMode != CRYPTMODE_OFF) {
    errorOut("Turning encryption on for '" + tapeDrive + "' failed!");
  } else {
    errorOut("Turning encryption off for '" + tapeDrive + "' failed!");
  }
}
// exits to shell with an error message

void errorOut(std::string const message) {
  std::cerr << "Error: " << message << "\n";
  showUsage();
  exit(EXIT_FAILURE);
}

// shows the command usage
void showUsage() {
  std::cout
      << "Usage: stenc --version | -g <length> -k <file> [-kd <description>] | "
         "-f <device> [--detail] [-e <on/mixed/rawread/off> [-k <file>] "
	     "[-kd <description>] [-a <index>] [--protect | --unprotect] [--ckod] ]\n\n"
         "Type 'man stenc' for more information.\n";
}
void inquiryDrive(std::string tapeDevice) {
  // todo: std::cout should not be used outside main()
  SCSI_PAGE_INQ *const iresult = SCSIGetInquiry(tapeDevice);
  std::cout << std::left << std::setw(25) << "Device Mfg:";
  std::cout.write((const char *)iresult->vender, 8);
  std::cout << std::endl;
  std::cout << std::left << std::setw(25) << "Product ID:";
  std::cout.write((const char *)iresult->productID, 16);
  std::cout << std::endl;
  std::cout << std::left << std::setw(25) << "Product Revision:";
  std::cout.write((const char *)iresult->productRev, 4);
  std::cout << std::endl;

  delete iresult;
}

void showDriveStatus(std::string tapeDrive, bool detail) {
  SSP_DES *opt = SSPGetDES(tapeDrive);
  if (opt == NULL)
    return;
  std::string emode = "unknown";
  std::cout << std::left << std::setw(25) << "Drive Encryption:";
  if ((int)opt->des.encryptionMode == 0x2 && // encrypt
      (int)opt->des.decryptionMode == 0x2    // read only encrypted data
  )
    emode = "on";
  if ((int)opt->des.encryptionMode == 0x2 && // encrypt
      (int)opt->des.decryptionMode == 0x3    // read encrypted and unencrypted
  )
    emode = "mixed";

  if ((int)opt->des.encryptionMode == 0x2 && // encrypt
      (int)opt->des.decryptionMode == 0x1    // read encrypted and unencrypted
  )
    emode = "rawread";

  if ((int)opt->des.encryptionMode == 0x0 && // encrypt
      (int)opt->des.decryptionMode == 0x0    // read encrypted and unencrypted
  )
    emode = "off";

  std::cout << emode << "\n";
  if (detail) {
    std::cout << std::left << std::setw(25) << "Drive Output:";
    switch ((int)opt->des.decryptionMode) {
    case 0x0:
      std::cout << "Not decrypting\n";
      std::cout << std::setw(25) << " "
                << "Raw encrypted data not outputted\n";
      break;
    case 0x1:
      std::cout << "Not decrypting\n";
      std::cout << std::setw(25) << " "
                << "Raw encrypted data outputted\n";
      break;
    case 0x2:
      std::cout << "Decrypting\n";
      std::cout << std::setw(25) << " "
                << "Unencrypted data not outputted\n";
      break;
    case 0x3:
      std::cout << "Decrypting\n";
      std::cout << std::setw(25) << " "
                << "Unencrypted data outputted\n";
      break;
    default:
      std::cout << "Unknown '0x" << std::hex << (int)opt->des.decryptionMode
                << "' \n";
      break;
    }
    std::cout << std::setw(25) << "Drive Input:";
    switch ((int)opt->des.encryptionMode) {
    case 0x0:
      std::cout << "Not encrypting\n";
      break;
    case 0x2:
      std::cout << "Encrypting\n";
      break;
    default:
      std::cout << "Unknown result '0x" << std::hex
                << (int)opt->des.encryptionMode << "'\n";
      break;
    }
    if (opt->des.RDMD == 1) {
      std::cout << std::setw(25) << " "
                << "Protecting from raw read\n";
    }

    std::cout << std::setw(25) << "Key Instance Counter:" << std::dec
              << BSLONG(opt->des.keyInstance) << "\n";
    if (opt->des.algorithmIndex != 0) {
      std::cout << std::setw(25) << "Encryption Algorithm:" << std::hex
                << (int)opt->des.algorithmIndex << "\n";
    }
  }
  if (opt->kads.size() > 0) {
    for (unsigned int i = 0; i < opt->kads.size(); i++) {
      std::stringstream lbl{};
      lbl << "Drive Key Desc.(";
      switch (opt->kads[i].type) {
      case KAD_TYPE_UKAD:
        lbl << "uKAD): ";
        std::cout << std::setw(25) << lbl.str();
        std::cout.write((const char *)&opt->kads[i].descriptor,
                        BSSHORT(opt->kads[i].descriptorLength));
        std::cout << std::endl;
        break;
      case KAD_TYPE_AKAD:
        lbl << "aKAD): ";
        std::cout << std::setw(25) << lbl.str();
        std::cout.write((const char *)&opt->kads[i].descriptor,
                        BSSHORT(opt->kads[i].descriptorLength));
        std::cout << std::endl;
        break;
      }
    }
  }

  delete opt;
}

void showVolumeStatus(std::string tapeDrive) {
  SSP_NBES *opt = SSPGetNBES(tapeDrive, true);
  if (opt == NULL)
    return;
  if (opt->nbes.compressionStatus != 0) {
    std::cout << std::left << std::setw(25) << "Volume Compressed:";
    switch (opt->nbes.compressionStatus) {
    case 0x00:
      std::cout << "Drive cannot determine\n";
      break;
    default:
      std::cout << "Unknown result '" << std::hex
                << (int)opt->nbes.compressionStatus << "'\n";
      break;
    }
  }
  std::cout << std::left << std::setw(25) << "Volume Encryption:";
  switch ((int)opt->nbes.encryptionStatus) {
  case 0x01:
    std::cout << "Unable to determine\n";
    break;
  case 0x02:
    std::cout << "Logical block is not a logical block\n";
    break;
  case 0x03:
    std::cout << "Not encrypted\n";
    break;
  case 0x05:
    std::cout << "Encrypted and able to decrypt\n";
    if (opt->nbes.RDMDS == 1)
      std::cout << std::left << std::setw(25)
                << " Protected from raw read\n";
    break;
  case 0x06:
    std::cout << "Encrypted, but unable to decrypt due to invalid key.\n";
    if (opt->kads.size() > 0) {
      for (unsigned int i = 0; i < opt->kads.size(); i++) {
        std::stringstream lbl;
        lbl << "Volume Key Desc.(";
        switch (opt->kads[i].type) {
        case KAD_TYPE_UKAD:
          lbl << "uKAD): ";
          std::cout << std::setw(25) << lbl.str();
          std::cout.write((const char *)&opt->kads[i].descriptor,
                          BSSHORT(opt->kads[i].descriptorLength));
          std::cout << std::endl;
          break;
        case KAD_TYPE_AKAD:
          lbl << "aKAD): ";
          std::cout << std::setw(25) << lbl.str();
          std::cout.write((const char *)&opt->kads[i].descriptor,
                          BSSHORT(opt->kads[i].descriptorLength));
          std::cout << std::endl;
          break;
        }
      }
    }
    if (opt->nbes.RDMDS == 1)
      std::cout << std::left << std::setw(25) << " Protected from raw read\n";
    break;

  default:
    std::cout << "Unknown result '" << std::hex
              << (int)opt->nbes.encryptionStatus << "'\n";
    break;
  }
  if (opt->nbes.algorithmIndex != 0) {
    std::cout << std::left << std::setw(25)
              << "Volume Algorithm:" << (int)opt->nbes.algorithmIndex << "\n";
  }

  delete opt;
}

void echo(bool on = true) {
  struct termios settings {};
  tcgetattr(STDIN_FILENO, &settings);
  settings.c_lflag =
      on ? (settings.c_lflag | ECHO) : (settings.c_lflag & ~(ECHO));
  tcsetattr(STDIN_FILENO, TCSANOW, &settings);
}

std::string timestamp() {
  time_t tm{};
  time(&tm);
  char buffer[80];
  int len = strftime((char *)&buffer, 80, "%Y-%m-%d", localtime(&tm));
  std::string val;
  val.assign(buffer, len);
  return (val);
}

std::string randomKey(int length) {
  unsigned char rnd;
  std::stringstream retval{};
  std::ifstream random{};

  // Under Linux and AIX /dev/random provides much more cryptographically secure
  // random output than rand()
  random.open("/dev/random", std::ios::in | std::ios::binary);
  if (random.is_open()) {
    for (int i = 0; i < length; i++) {
      random.read(reinterpret_cast<char *>(&rnd), 1);
      retval << std::hex << std::setfill('0') << setw(2) << static_cast<int>(rnd);
    }
    random.close();
  } else {
    std::cout << "Enter random keys on the keyboard to seed the generator.\n"
                 "End by pressing enter...\n";

    double check = 0;
    char c = 0;
    echo(false);
    while (c != 10) {
      check += (int)c;
      c = getchar();
    }
    echo(true);
    srand(time(NULL) + (int)check);
    for (int i = 0; i < length; i++) {
      retval << std::hex << (std::rand() % 256);
    }
  }
  retval << std::endl;
  return (retval.str());
}
