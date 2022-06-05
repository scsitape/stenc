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

#include <cerrno>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>

#include <fcntl.h>
#include <sys/ioctl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(OS_LINUX)
#include <scsi/scsi.h>
#include <scsi/sg.h>
#define SCSI_TIMEOUT 5000
#elif defined(OS_FREEBSD)
#include <cam/scsi/scsi_message.h>
#include <camlib.h>
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

#define BSINTTOCHAR(x)                                                         \
  static_cast<std::uint8_t>((x) >> 24), static_cast<std::uint8_t>((x) >> 16),  \
      static_cast<std::uint8_t>((x) >> 8), static_cast<std::uint8_t>((x))

// generic_deleter permits the use of std::unique_ptr for RAII on non-pointer
// types like file descriptors.
template <typename T, T null_value, typename Deleter, Deleter d>
struct generic_deleter {
  class pointer {
    T t;

  public:
    pointer() : t {null_value} {}
    pointer(T t) : t {t} {}
    pointer(std::nullptr_t) : t {null_value} {}
    explicit operator bool() const noexcept { return t != null_value; }
    friend bool operator==(pointer lhs, pointer rhs) noexcept
    {
      return lhs.t == rhs.t;
    }
    friend bool operator!=(pointer lhs, pointer rhs) noexcept
    {
      return !(lhs == rhs);
    }
    operator T() const noexcept { return t; }
  };

  void operator()(pointer p) const noexcept { d(p); }
};
using unique_fd =
    std::unique_ptr<int, generic_deleter<int, -1, decltype(&close), &close>>;

enum class scsi_direction { to_device, from_device };

static void scsi_execute(const std::string& device, const std::uint8_t *cmd_p,
                         std::size_t cmd_len, std::uint8_t *dxfer_p,
                         std::size_t dxfer_len, scsi_direction direction)
{
#if defined(OS_LINUX)
  unique_fd fd {open(device.c_str(), O_RDONLY | O_NDELAY)};
  if (!fd) {
    std::ostringstream oss;
    oss << "Cannot open device " << device;
    throw std::system_error {errno, std::generic_category(), oss.str()};
  }

  sg_io_hdr cmdio {};
  auto sense_buf {std::make_unique<scsi::sense_buffer>()};

  cmdio.cmd_len = cmd_len;
  cmdio.dxfer_direction = (direction == scsi_direction::to_device)
                              ? SG_DXFER_TO_DEV
                              : SG_DXFER_FROM_DEV;
  cmdio.dxfer_len = dxfer_len;
  cmdio.dxferp = dxfer_p;
  cmdio.cmdp = const_cast<unsigned char *>(cmd_p);
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
  auto dev = std::unique_ptr<struct cam_device, decltype(&cam_close_device)> {
      cam_open_device(device.c_str(), O_RDWR), &cam_close_device};
  if (dev == nullptr) {
    std::ostringstream oss;
    oss << "Cannot open device " << device << ": " << cam_errbuf;
    throw std::runtime_error {oss.str()};
  }
  auto ccb = std::unique_ptr<union ccb, decltype(&cam_freeccb)> {
      cam_getccb(dev.get()), &cam_freeccb};
  if (ccb == nullptr) {
    throw std::bad_alloc {};
  }
  CCB_CLEAR_ALL_EXCEPT_HDR(&ccb->csio);

  cam_fill_csio(
      &ccb->csio, RETRYCOUNT, nullptr,
      CAM_PASS_ERR_RECOVER | CAM_CDB_POINTER |
          (direction == scsi_direction::to_device ? CAM_DIR_OUT : CAM_DIR_IN),
      MSG_SIMPLE_Q_TAG, dxfer_p, dxfer_len, SSD_FULL_SIZE, cmd_len,
      SCSI_TIMEOUT);
  ccb->csio.cdb_io.cdb_ptr = const_cast<u_int8_t *>(cmd_p);
  if (cam_send_ccb(dev.get(), ccb.get())) {
    throw std::system_error {errno, std::generic_category()};
  }
  if (ccb->csio.scsi_status) {
    auto sense_buf {std::make_unique<scsi::sense_buffer>()};
    std::memcpy(sense_buf->data(), &ccb->csio.sense_data,
                sizeof(scsi::sense_buffer));
    throw scsi::scsi_error {std::move(sense_buf)};
  }
#else
#error "OS type is not set"
#endif
}

namespace scsi {

bool is_device_ready(const std::string& device)
{
  const std::uint8_t test_unit_ready_cmd[6] {};

  try {
    scsi_execute(device, test_unit_ready_cmd, sizeof(test_unit_ready_cmd),
                 nullptr, 0u, scsi_direction::from_device);
    return true;
  } catch (const scsi::scsi_error& err) {
    return false;
  }
}

void get_des(const std::string& device, std::uint8_t *buffer,
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
  scsi_execute(device, spin_des_command, sizeof(spin_des_command), buffer,
               length, scsi_direction::from_device);
}

void get_nbes(const std::string& device, std::uint8_t *buffer,
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
  scsi_execute(device, spin_nbes_command, sizeof(spin_nbes_command), buffer,
               length, scsi_direction::from_device);
}

void get_dec(const std::string& device, std::uint8_t *buffer,
             std::size_t length)
{
  const std::uint8_t spin_dec_command[] {
      SSP_SPIN_OPCODE,
      SSP_SP_PROTOCOL_TDE,
      0x00,
      0x10,
      0,
      0,
      BSINTTOCHAR(length),
      0,
      0,
  };
  scsi_execute(device, spin_dec_command, sizeof(spin_dec_command), buffer,
               length, scsi_direction::from_device);
}

inquiry_data get_inquiry(const std::string& device)
{
  const std::uint8_t scsi_inq_command[] {
      0x12, 0, 0, 0, sizeof(inquiry_data), 0,
  };
  inquiry_data inq {};
  scsi_execute(device, scsi_inq_command, sizeof(scsi_inq_command),
               reinterpret_cast<std::uint8_t *>(&inq), sizeof(inq),
               scsi_direction::from_device);
  return inq;
}

std::unique_ptr<const std::uint8_t[]>
make_sde(encrypt_mode enc_mode, decrypt_mode dec_mode,
         std::uint8_t algorithm_index, const std::vector<std::uint8_t>& key,
         const std::string& key_name, kadf kad_format, sde_rdmc rdmc, bool ckod)
{
  std::size_t length {sizeof(page_sde) + key.size()};
  if (!key_name.empty()) {
    length += sizeof(kad) + key_name.size();
  }
  auto buffer {std::make_unique<std::uint8_t[]>(length)};
  auto& page {reinterpret_cast<page_sde&>(*buffer.get())};

  page.page_code = htons(0x10);
  page.length = htons(length - sizeof(page_header));
  page.control = std::byte {2u}
                 << page_sde::control_scope_pos; // all IT nexus = 10b
  // no external encryption mode check for widest compatibility of reads
  page.flags |= std::byte {1u} << page_sde::flags_ceem_pos;
  page.flags |= std::byte {static_cast<std::underlying_type_t<sde_rdmc>>(rdmc)};
  if (ckod) {
    page.flags |= page_sde::flags_ckod_mask;
  }
  page.encryption_mode = enc_mode;
  page.decryption_mode = dec_mode;
  page.algorithm_index = algorithm_index;
  page.kad_format = kad_format;
  page.key_length = htons(key.size());
  std::memcpy(page.key, key.data(), key.size());

  if (!key_name.empty()) {
    auto& ukad {reinterpret_cast<kad&>(
        *(buffer.get() + sizeof(page_sde) + key.size()))};
    ukad.length = htons(key_name.size());
    std::memcpy(ukad.descriptor, key_name.data(), key_name.size());
  }

  return buffer;
}

void write_sde(const std::string& device, const std::uint8_t *sde_buffer)
{
  auto& page {reinterpret_cast<const page_sde&>(*sde_buffer)};
  std::size_t length {sizeof(page_header) + ntohs(page.length)};
  const std::uint8_t spout_sde_command[] {
      SSP_SPOUT_OPCODE,
      SSP_SP_PROTOCOL_TDE,
      0,
      0X10,
      0,
      0,
      BSINTTOCHAR(length),
      0,
      0,
  };

  scsi_execute(device, spout_sde_command, sizeof(spout_sde_command),
               const_cast<std::uint8_t *>(sde_buffer), length,
               scsi_direction::to_device);
}

void print_sense_data(std::ostream& os, const sense_data& sd)
{
  os << std::left << std::setw(25) << "Sense Code: ";

  auto sense_key {sd.flags & sense_data::flags_sense_key_mask};

  switch (sense_key) {
  case sense_data::no_sense:
    os << "No specific error";
    break;
  case sense_data::recovered_error:
    os << "Recovered error";
    break;
  case sense_data::not_ready:
    os << "Device not ready";
    break;
  case sense_data::medium_error:
    os << "Medium Error";
    break;
  case sense_data::hardware_error:
    os << "Hardware Error";
    break;
  case sense_data::illegal_request:
    os << "Illegal Request";
    break;
  case sense_data::unit_attention:
    os << "Unit Attention";
    break;
  case sense_data::data_protect:
    os << "Data protect";
    break;
  case sense_data::blank_check:
    os << "Blank tape";
    break;
  }

  os << " (0x" << HEX(sense_key) << ")\n";

  os << std::left << std::setw(25) << " ASC:"
     << "0x" << HEX(sd.additional_sense_code) << '\n';

  os << std::left << std::setw(25) << " ASCQ:"
     << "0x" << HEX(sd.additional_sense_qualifier) << '\n';

  if (sd.additional_sense_length > 0) {
    os << std::left << std::setw(25) << " Additional data: "
       << "0x";

    for (int i = 0; i < sd.additional_sense_length; i++) {
      os << HEX(sd.additional_sense_bytes[i]);
    }
    os << '\n';
  }
#ifdef DEBUGSCSI
  os << std::left << std::setw(25) << " Raw Sense:"
     << "0x";
  char *rawsense = (char *)&sd;

  for (int i = 0; i < sense_data::maximum_size; i++) {
    os << HEX(rawsense[i]);
  }
  os << '\n';
#endif
}

std::vector<std::reference_wrapper<const algorithm_descriptor>>
read_algorithms(const page_dec& page)
{
  auto it {reinterpret_cast<const std::uint8_t *>(&page.ads[0])};
  const auto end {reinterpret_cast<const std::uint8_t *>(&page) +
                  ntohs(page.length) + sizeof(page_header)};
  std::vector<std::reference_wrapper<const algorithm_descriptor>> v {};

  while (it < end) {
    auto elem {reinterpret_cast<const algorithm_descriptor *>(it)};
    v.push_back(std::cref(*elem));
    it += ntohs(elem->length) + 4u; // length field + preceding 4 byte header
  }
  return v;
}

} // namespace scsi
