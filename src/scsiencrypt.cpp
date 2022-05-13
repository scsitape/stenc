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
#include <config.h>

#include <bitset>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#if defined(OS_LINUX)
#include <scsi/scsi.h>
#include <scsi/sg.h>
#define SCSI_TIMEOUT 5000
#elif defined(OS_FREEBSD)
#include <camlib.h>
#include <cam/scsi/scsi_message.h>
#define SCSI_TIMEOUT 5000
#else
#error "OS type is not set"
#endif

#include "scsiencrypt.h"

constexpr std::uint8_t SSP_SPIN_OPCODE = 0xa2;
constexpr std::uint8_t SSP_SPOUT_OPCODE = 0xb5;
constexpr std::uint8_t SSP_SP_CMD_LEN = 12;
constexpr std::uint8_t SSP_SP_PROTOCOL_TDE = 0x20;

constexpr int RETRYCOUNT = 1;

#define BSINTTOCHAR(x) \
  static_cast<std::uint8_t>((x) >> 24), \
  static_cast<std::uint8_t>((x) >> 16), \
  static_cast<std::uint8_t>((x) >> 8), \
  static_cast<std::uint8_t>((x))

// generic_deleter permits the use of std::unique_ptr for RAII on non-pointer
// types like file descriptors.
template<typename T, T null_value, typename Deleter, Deleter d>
struct generic_deleter {
  class pointer {
    T t;
  public:
    pointer() : t {null_value} {}
    pointer(T t) : t {t} {}
    pointer(std::nullptr_t) : t {null_value} {}
    explicit operator bool() const noexcept { return t != null_value; }
    friend bool operator ==(pointer lhs, pointer rhs) noexcept { return lhs.t == rhs.t; }
    friend bool operator !=(pointer lhs, pointer rhs) noexcept { return !(lhs == rhs); }
    operator T() const noexcept { return t; }
  };

  void operator()(pointer p) const noexcept { d(p); }
};
using unique_fd = std::unique_ptr<int, generic_deleter<int, -1, decltype(&close), &close>>;

void byteswap(unsigned char *array, int size, int value);
bool moveTape(const std::string& tapeDevice, int count, bool dirForward);
void outputSense(SCSI_PAGE_SENSE *sd);
bool SCSIExecute(const std::string& tapedevice, unsigned char *cmd_p, int cmd_len,
                 unsigned char *dxfer_p, int dxfer_len, bool cmd_to_device,
                 bool show_error);

enum class scsi_direction { to_device, from_device };

static void scsi_execute(const std::string& device, const std::uint8_t *cmd_p,
                         std::size_t cmd_len, const std::uint8_t *dxfer_p,
                         std::size_t dxfer_len, scsi_direction direction)
{
#if defined(OS_LINUX)
  unique_fd fd {open(device.c_str(), O_RDONLY)};
  if (!fd) {
    std::ostringstream oss;
    oss << "Cannot open device " << device;
    throw std::system_error {errno, std::generic_category(), oss.str()};
  }

  sg_io_hdr cmdio {};
  auto sense_buf {std::make_unique<scsi::sense_buffer>()};

  cmdio.cmd_len = cmd_len;
  cmdio.dxfer_direction = (direction == scsi_direction::to_device)
                          ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
  cmdio.dxfer_len = dxfer_len;
  cmdio.dxferp = const_cast<unsigned char*>(dxfer_p);
  cmdio.cmdp = const_cast<unsigned char*>(cmd_p);
  cmdio.sbp = sense_buf->data();
  cmdio.mx_sb_len = sizeof(decltype(sense_buf)::element_type);
  cmdio.timeout = SCSI_TIMEOUT;
  cmdio.interface_id = 'S';

  if (ioctl(fd.get(), SG_IO, &cmdio)) {
    throw std::system_error {errno, std::generic_category()};
  }
  if (cmdio.status) {
    throw scsi::scsi_error {std::move(sense_buf)};
  }
#elif defined(OS_FREEBSD)
  auto dev = std::unique_ptr<struct cam_device, decltype(&cam_close_device)>
    {cam_open_device(device.c_str(), O_RDWR), &cam_close_device};
  if (dev == nullptr) {
    std::ostringstream oss;
    oss << "Cannot open device " << device << ": " << cam_errbuf;
    throw std::runtime_error {oss.str()};
  }
  auto ccb = std::unique_ptr<union ccb, decltype(&cam_freeccb)>
    {cam_getccb(dev.get()), &cam_freeccb};
  if (ccb == nullptr) {
    throw std::bad_alloc {};
  }
  CCB_CLEAR_ALL_EXCEPT_HDR(&ccb->csio);

  cam_fill_csio(&ccb->csio, RETRYCOUNT, nullptr,
                CAM_PASS_ERR_RECOVER | CAM_CDB_POINTER |
                  (direction == scsi_direction::to_device ? CAM_DIR_OUT : CAM_DIR_IN),
                MSG_SIMPLE_Q_TAG, const_cast<u_int8_t*>(dxfer_p),
                dxfer_len, SSD_FULL_SIZE, cmd_len, SCSI_TIMEOUT);
  ccb->csio.cdb_io.cdb_ptr = const_cast<u_int8_t*>(cmd_p);
  if (cam_send_ccb(dev.get(), ccb.get())) {
    throw std::system_error {errno, std::generic_category()};
  }
  if (ccb->csio.scsi_status) {
    auto sense_buf {std::make_unique<scsi::sense_buffer>()};
    std::memcpy(sense_buf->data(), &ccb->csio.sense_data, sizeof(scsi::sense_buffer));
    throw scsi::scsi_error {std::move(sense_buf)};
  }
#else
#error "OS type is not set"
#endif
}

namespace scsi {

void get_des(const std::string& device, const std::uint8_t *buffer,
             std::size_t length)
{
  const std::uint8_t spin_des_command[] {
    SSP_SPIN_OPCODE,
    SSP_SP_PROTOCOL_TDE,
    0,
    0X20,
    0,
    0,
    BSINTTOCHAR(length),
    0,
    0,
  };
  scsi_execute(device, spin_des_command, sizeof(spin_des_command),
               buffer, length, scsi_direction::from_device);
}

void get_nbes(const std::string& device, const std::uint8_t *buffer,
              std::size_t length)
{
  const std::uint8_t spin_nbes_command[] {
    SSP_SPIN_OPCODE,
    SSP_SP_PROTOCOL_TDE,
    0,
    0X21,
    0,
    0,
    BSINTTOCHAR(length),
    0,
    0,
  };
  scsi_execute(device, spin_nbes_command, sizeof(spin_nbes_command),
               buffer, length, scsi_direction::from_device);
}

void get_dec(const std::string& device, const std::uint8_t *buffer,
             std::size_t length)
{
  const uint8_t spin_dec_command[] {
    SSP_SPIN_OPCODE,
    SSP_SP_PROTOCOL_TDE,
    0x00, 0x10,
    0,
    0,
    BSINTTOCHAR(length),
    0,
    0,
  };
  scsi_execute(device, spin_dec_command, sizeof(spin_dec_command),
               buffer, length, scsi_direction::from_device);
}

inquiry_data get_inquiry(const std::string& device)
{
  const uint8_t scsi_inq_command[] {0x12, 0, 0, 0, sizeof(inquiry_data), 0};
  inquiry_data inq;
  scsi_execute(device, scsi_inq_command, sizeof(scsi_inq_command),
               reinterpret_cast<const std::uint8_t*>(&inq), sizeof(inq),
               scsi_direction::from_device);
  return inq;
}

std::unique_ptr<const std::uint8_t[]> make_sde(encrypt_mode enc_mode,
                                               decrypt_mode dec_mode,
                                               std::uint8_t algorithm_index,
                                               const std::vector<std::uint8_t> key,
                                               const std::string& key_name,
                                               sde_rdmc rdmc, bool ckod)
{
  std::size_t length {sizeof(page_sde) + key.size()};
  if (!key_name.empty()) {
    length += sizeof(kad) + key_name.size();
  }
  auto buffer {std::make_unique<std::uint8_t[]>(length)};
  auto& page {reinterpret_cast<page_sde&>(*buffer.get())};

  page.page_code = htons(0x10);
  page.length = htons(length - sizeof(page_header));
  page.control = std::byte {2u} << page_sde::control_scope_pos; // all IT nexus = 10b
  page.flags |= std::byte {DEFAULT_CEEM} << page_sde::flags_ceem_pos;
  page.flags |= std::byte {rdmc};
  if (ckod) {
    page.flags |= page_sde::flags_ckod_mask;
  }
  page.encryption_mode = enc_mode;
  page.decryption_mode = dec_mode;
  page.algorithm_index = algorithm_index;
  page.key_length = htons(key.size());
  std::memcpy(page.key, key.data(), key.size());

  if (!key_name.empty()) {
    auto &ukad {reinterpret_cast<kad&>(*(buffer.get() + sizeof(page_sde) + key.size()))};
    ukad.length = htons(key_name.size());
    std::memcpy(ukad.descriptor, key_name.data(), key_name.size());
  }

  return buffer;
}

void write_sde(const std::string& device, const std::uint8_t *sde_buffer)
{
  auto& page {reinterpret_cast<const page_sde&>(*sde_buffer)};
  std::size_t length {sizeof(page_header) + ntohs(page.length)};
  const uint8_t spout_sde_command[] {
    SSP_SPOUT_OPCODE,
    SSP_SP_PROTOCOL_TDE,
    0,
    0X10,
    0,
    0,
    BSINTTOCHAR(length),
    0,
    0
  };

  scsi_execute(device, spout_sde_command, sizeof(spout_sde_command),
               sde_buffer, length, scsi_direction::to_device);
}

void print_sense_data(std::ostream& os, const sense_data& sd) {
  os << std::left << std::setw(25) << "Sense Code: ";

  auto sense_key {static_cast<unsigned int>(sd.flags & sense_data::flags_sense_key_mask)};

  switch (sense_key) {
  case 0u:
    os << "No specific error";
    break;
  case 2u:
    os << "Device not ready";
    break;
  case 3u:
    os << "Medium Error";
    break;
  case 4u:
    os << "Hardware Error";
    break;
  case 5u:
    os << "Illegal Request";
    break;
  case 6u:
    os << "Unit Attention";
    break;
  case 7u:
    os << "Data protect";
    break;
  case 8u:
    os << "Blank tape";
    break;
  }

  os << " (0x" << HEX(sense_key) << ")\n";

  os << std::left << std::setw(25) << " ASC:"
     << "0x" << HEX(sd.additional_sense_code) << "\n";

  os << std::left << std::setw(25) << " ASCQ:"
     << "0x" << HEX(sd.additional_sense_qualifier) << "\n";

  if (sd.additional_sense_length > 0) {
    os << std::left << std::setw(25) << " Additional data: " << "0x";

    for (int i = 0; i < sd.additional_sense_length; i++) {
      os <<  HEX(sd.additional_sense_bytes[i]);
    }
    os << "\n";
  }
#ifdef DEBUGSCSI
  os << std::left << std::setw(25) << " Raw Sense:"
     << "0x";
  char *rawsense = (char *)&sd;

  for (int i = 0; i < sense_data::maximum_size; i++) {
    os << HEX(rawsense[i]);
  }
  os << "\n";
#endif
}

}

// Gets encryption options on the tape drive
SSP_DES *SSPGetDES(const std::string& tapeDevice) {
  const uint8_t spin_des_command[] {
    SSP_SPIN_OPCODE,
    SSP_SP_PROTOCOL_TDE,
    0,
    0X20,
    0,
    0,
    BSINTTOCHAR(sizeof(SSP_PAGE_BUFFER)),
    0,
    0,
  };
  SSP_PAGE_BUFFER buffer;
  memset(&buffer, 0, sizeof(SSP_PAGE_BUFFER));
  if (!SCSIExecute(tapeDevice, (unsigned char *)&spin_des_command,
                   sizeof(spin_des_command), (unsigned char *)&buffer,
                   sizeof(SSP_PAGE_BUFFER), false, true)) {
    return NULL;
  }
  SSP_DES *status = new SSP_DES(&buffer);
  return status;
}

// Gets encryption options on the tape drive
SSP_NBES *SSPGetNBES(const std::string& tapeDevice, bool retry) {
  const uint8_t spin_nbes_command[] {
    SSP_SPIN_OPCODE,
    SSP_SP_PROTOCOL_TDE,
    0,
    0X21,
    0,
    0,
    BSINTTOCHAR(sizeof(SSP_PAGE_BUFFER)),
    0,
    0,
  };
  SSP_PAGE_BUFFER buffer;
  memset(&buffer, 0, sizeof(SSP_PAGE_BUFFER));
  if (!SCSIExecute(tapeDevice, (unsigned char *)&spin_nbes_command,
                   sizeof(spin_nbes_command), (unsigned char *)&buffer,
                   sizeof(SSP_PAGE_BUFFER), false, false)) {
    return NULL;
  }
  SSP_NBES *status = new SSP_NBES(&buffer);
  if (status->nbes.encryptionStatus == 0x01 && retry) {
    // move to the start of the tape and try again
    int moves = 0;
    while (true) {
      if (status == NULL)
        break;
      if (status->nbes.encryptionStatus != 0x01)
        break;
      if (moves >= MAX_TAPE_READ_BLOCKS)
        break;
      delete status;
      status = NULL; // double free bug fix provided by Adam Nielsen
      if (!moveTape(tapeDevice, 1, true))
        break;
      moves++;
      status = SSPGetNBES(tapeDevice, false);
    }
    moveTape(tapeDevice, moves, false);
  }
  return status;
}

// Sends and inquiry to the device
SCSI_PAGE_INQ *SCSIGetInquiry(const std::string& tapeDevice) {
  const uint8_t scsi_inq_command[] {0x12, 0, 0, 0, sizeof(SCSI_PAGE_INQ), 0};
  SCSI_PAGE_INQ *status = new SCSI_PAGE_INQ;
  memset(status, 0, sizeof(SCSI_PAGE_INQ));
  if (!SCSIExecute(tapeDevice, (unsigned char *)&scsi_inq_command,
                   sizeof(scsi_inq_command), (unsigned char *)status,
                   sizeof(SCSI_PAGE_INQ), false, true)) {
    exit(EXIT_FAILURE);
  }
  return status;
}

int SCSIInitSDEPage(SCSIEncryptOptions *eOptions,
                    uint8_t *buffer) {
  SSP_PAGE_SDE options;
  // copy the template over the options
  memset(&options, 0, sizeof(SSP_PAGE_SDE));
  byteswap((unsigned char *)&options.pageCode, 2, 0x10);
  int pagelen = sizeof(SSP_PAGE_SDE);
  options.scope = 2; // all IT nexus = 10b
  options.RDMC = eOptions->rdmc;
  options.ckod = (eOptions->CKOD) ? 1 : 0;
  options.CEEM = DEFAULT_CEEM;
  options.algorithmIndex = eOptions->algorithmIndex;
  // set the specific options
  switch (eOptions->cryptMode) {
    case CRYPTMODE_ON: // encrypt, read only encrypted data
      options.encryptionMode = 2;
      options.decryptionMode = 2;
      break;
    case CRYPTMODE_MIXED: // encrypt, read all data
      options.encryptionMode = 2;
      options.decryptionMode = 3;
      break;
    case CRYPTMODE_RAWREAD:
      options.encryptionMode = 2;
      options.decryptionMode = 1;
      break;
    default:
      byteswap((unsigned char *)options.keyLength, 2, DEFAULT_KEYSIZE);
      eOptions->cryptoKey.clear(); // blank the key
      eOptions->keyName.clear(); // blank the key name, not supported when turned off
      break;
  }

  if (!eOptions->cryptoKey.empty()) {
    // byte swap the keylength
    byteswap((unsigned char *)&options.keyLength, 2,
             eOptions->cryptoKey.size());
    // copy the crypto key into the options
    std::copy(eOptions->cryptoKey.begin(), eOptions->cryptoKey.end(), options.keyData);
  }
  // create the key descriptor
  if (!eOptions->keyName.empty()) {
    SSP_KAD kad;
    memset(&kad, 0, sizeof(kad));
    // set the descriptor length to the length of the keyName
    byteswap((unsigned char *)&kad.descriptorLength, 2,
             eOptions->keyName.size());

    // get the size of the kad object
    int kadlen = eOptions->keyName.size() + SSP_KAD_HEAD_LENGTH;
    // increment the SPOUT page len
    pagelen += kadlen;
    // increase the page size
    eOptions->keyName.copy((char *)&kad.descriptor, eOptions->keyName.size(),
                           0);
    // copy the kad after the SDE command
    memcpy(&buffer[sizeof(SSP_PAGE_SDE)], &kad, kadlen);
  }
  // update the pagelen in options
  byteswap((unsigned char *)&options.length, 2,
           pagelen - 4); // set the page length, minus the length and pageCode

  // copy the options to the beginning of the buffer
  memcpy(buffer, &options, sizeof(SSP_PAGE_SDE));
  return pagelen;
}

// Writes encryption options to the tape drive
bool SCSIWriteEncryptOptions(const std::string& tapeDevice,
                             SCSIEncryptOptions *eOptions) {
  uint8_t buffer[1024] {};
  int pagelen = SCSIInitSDEPage(eOptions, buffer);

  const uint8_t spout_sde_command[] {
    SSP_SPOUT_OPCODE,
    SSP_SP_PROTOCOL_TDE,
    0,
    0X10,
    0,
    0,
    BSINTTOCHAR(pagelen),
    0,
    0,
  };

  // return whether or not the command executed
  return SCSIExecute(tapeDevice, (unsigned char *)&spout_sde_command,
                     sizeof(spout_sde_command), (unsigned char *)&buffer,
                     pagelen, true, true);
}

bool SCSIExecute(const std::string& tapedrive, unsigned char *cmd_p, int cmd_len,
                 unsigned char *dxfer_p, int dxfer_len, bool cmd_to_device,
                 bool show_error) {
  const char *tapedevice = tapedrive.c_str();
  int sg_fd, eresult, sresult, ioerr, retries;
  SCSI_PAGE_SENSE *sd = new SCSI_PAGE_SENSE;
  memset(sd, 0, sizeof(SCSI_PAGE_SENSE));

#if defined(OS_LINUX)
  sg_fd = open(tapedevice, O_RDONLY);
  if (sg_fd == -1) {
    std::cerr << "Could not open device '" << tapedevice << "': "
              << strerror(errno) << "\n";
    exit(EXIT_FAILURE);
  }

  sg_io_hdr cmdio;
  memset(&cmdio, 0, sizeof(sg_io_hdr));
  cmdio.cmd_len = cmd_len;
  cmdio.dxfer_direction = (cmd_to_device) ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
  cmdio.dxfer_len = dxfer_len;
  cmdio.dxferp = dxfer_p;
  cmdio.cmdp = cmd_p;
  cmdio.sbp = (unsigned char *)sd;
  cmdio.mx_sb_len = sizeof(SCSI_PAGE_SENSE);
  cmdio.timeout = SCSI_TIMEOUT;
  cmdio.interface_id = 'S';
  retries = 0;
  do {
    errno = 0;
    eresult = ioctl(sg_fd, SG_IO, &cmdio);
    if (eresult != 0)
      ioerr = errno;
    retries++;
  } while (errno != 0 && retries <= RETRYCOUNT);

  sresult = cmdio.status;
  close(sg_fd);
#elif defined(OS_FREEBSD)
  auto dev = cam_open_device(tapedevice, O_RDWR);
  auto ccb = dev ? cam_getccb(dev) : nullptr;

  if (dev == nullptr || ccb == nullptr) {
    std::cerr << "Could not open device '" << tapedevice << "': " << cam_errbuf << "\n";
    exit(EXIT_FAILURE);
  }
  CCB_CLEAR_ALL_EXCEPT_HDR(&ccb->csio);

  cam_fill_csio(&ccb->csio, RETRYCOUNT, nullptr,
                CAM_PASS_ERR_RECOVER | CAM_CDB_POINTER |
                    (cmd_to_device ? CAM_DIR_OUT : CAM_DIR_IN),
                MSG_SIMPLE_Q_TAG, dxfer_p, dxfer_len, SSD_FULL_SIZE, cmd_len,
                SCSI_TIMEOUT);
  ccb->csio.cdb_io.cdb_ptr = cmd_p;
  eresult = cam_send_ccb(dev, ccb);
  if (eresult != 0) {
    ioerr = errno;
  }
  sresult = ccb->csio.scsi_status;
  memcpy(sd, &ccb->csio.sense_data, sizeof(SCSI_PAGE_SENSE));

  cam_freeccb(ccb);
  cam_close_device(dev);
#else
#error "OS type is not set"
#endif
#ifdef DEBUGSCSI
  std::cout << "SCSI Command: ";
  for (int i = 0; i < cmd_len; i++) {
    std::cout << HEX(cmd_p[i]);
  }
  std::cout << "\n";

  std::cout << "SCSI Data: ";
  for (int i = 0; i < dxfer_len; i++) {
    std::cout << HEX(dxfer_p[i]);
  }
  std::cout << std::endl;
#endif

  bool retval = true;

  if (eresult != 0) {
    if (show_error) {
      std::cerr << "ERROR: " << strerror(ioerr) << "\n";
    }
    retval = false;
  }

  if (sresult != 0) {
    if (show_error)
      outputSense(sd);
    retval = false;
  }
  delete sd;
  return retval;
}

void byteswap(unsigned char *array, int size, int value) {
  switch (size) {
  case 2:
    array[0] = (unsigned char)((value & 0xff00) >> 8);
    array[1] = (unsigned char)(value & 0x00ff);
    break;
  case 4:
    array[0] = (unsigned char)((value & 0xff000000) >> 24);
    array[1] = (unsigned char)((value & 0x00ff0000) >> 16);
    array[2] = (unsigned char)((value & 0x0000ff00) >> 8);
    array[3] = (unsigned char)(value & 0x000000ff);

    break;
  default:
    std::cout << "Unhandled byte swap length of " << size << std::endl;
    break;
  }
}

SCSIEncryptOptions::SCSIEncryptOptions() {
  cryptMode = CRYPTMODE_OFF;
  algorithmIndex = DEFAULT_ALGORITHM;
  cryptoKey = {};
  CKOD = false;
  keyName = "";
  rdmc = RDMC_DEFAULT;
}

SSP_NBES::SSP_NBES(const SSP_PAGE_BUFFER *buffer) {
  memset(&nbes, 0, sizeof(SSP_PAGE_NBES));
  memcpy(&nbes, buffer, sizeof(SSP_PAGE_NBES));
  loadKADs(buffer, sizeof(SSP_PAGE_NBES));
}

SSP_DES::SSP_DES(const SSP_PAGE_BUFFER *buffer) {
  memset(&des, 0, sizeof(SSP_PAGE_DES));
  memcpy(&des, buffer, sizeof(SSP_PAGE_DES));
  loadKADs(buffer, sizeof(SSP_PAGE_DES));
}

void KAD_CLASS::loadKADs(const SSP_PAGE_BUFFER *buffer, int start) {
  const char *rawbuff = (const char *)buffer;
  int length = BSSHORT(buffer->length) + 4;
  int pos = start;
  while (pos < length) {
    SSP_KAD kad;
    memset(&kad, 0, sizeof(SSP_KAD));
    memcpy(&kad, rawbuff + pos, SSP_KAD_HEAD_LENGTH);
    pos += SSP_KAD_HEAD_LENGTH;
    if (pos >= length)
      break;
    unsigned short kadDesLen = BSSHORT(kad.descriptorLength);
    if (kadDesLen > 0) {
      memcpy(&kad.descriptor, rawbuff + pos, kadDesLen);
      pos += kadDesLen;
    } else
      pos++;
    kads.push_back(kad);
  }
}

bool moveTape(const std::string& tapeDevice, int count, bool dirForward) {
  struct mtop mt_command;
  int sg_fd = open(tapeDevice.c_str(), O_RDONLY);
  if (!sg_fd || sg_fd == -1) {
    return false;
  }
  errno = 0;
  bool retval = true;
#if defined(OS_LINUX) || defined(OS_FREEBSD) // Linux or FreeBSD System

  mt_command.mt_op = (dirForward) ? MTFSR : MTBSR;
  mt_command.mt_count = count;
  ioctl(sg_fd, MTIOCTOP, &mt_command);
#else
#error "OS type is not set"
#endif
  if (errno != 0)
    retval = false;

  close(sg_fd);
  errno = 0;
  return retval;
}

void outputSense(SCSI_PAGE_SENSE *sd) {
  std::cerr << std::left << std::setw(25) << "Sense Code: ";

  switch ((int)sd->senseKey) {
  case 0:
    std::cerr << "No specific error";
    break;
  case 2:
    std::cerr << "Device not ready";
    break;
  case 3:
    std::cerr << "Medium Error";
    break;
  case 4:
    std::cerr << "Hardware Error";
    break;
  case 5:
    std::cerr << "Illegal Request";
    break;
  case 6:
    std::cerr << "Unit Attention";
    break;
  case 7:
    std::cerr << "Data protect";
    break;
  case 8:
    std::cerr << "Blank tape";
    break;
  }

  std::cerr << " (0x" << HEX(sd->senseKey) << ")\n";

  std::cerr << std::left << std::setw(25) << " ASC:"
            << "0x" << HEX(sd->addSenseCode) << "\n";

  std::cerr << std::left << std::setw(25) << " ASCQ:"
            << "0x" << HEX(sd->addSenseCodeQual) << "\n";

  if (sd->addSenseLen > 0) {
    std::cerr << std::left << std::setw(25) << " Additional data: " << "0x";

    for (int i = 0; i < sd->addSenseLen; i++) {
      std::cerr <<  HEX(sd->addSenseData[i]);
    }
    std::cerr << "\n";
  }
#ifdef DEBUGSCSI
  std::cerr << std::left << std::setw(25) << " Raw Sense:"
            << "0x";
  char *rawsense = (char *)sd;

  for (int i = 0; i < sizeof(SCSI_PAGE_SENSE); i++) {
    std::cerr << HEX(rawsense[i]);
  }
  std::cerr << "\n";
#endif
}
