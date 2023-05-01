.. SPDX-FileCopyrightText: 2022 stenc authors
..
.. SPDX-License-Identifier: GPL-2.0-or-later

=================================
STENC(1) |General Commands Manual
=================================

NAME
====

stenc - SCSI Tape Hardware Encryption Manager

SYNOPSIS
========

| **stenc** [**-f** *DEVICE*]
| **stenc** [**-f** *DEVICE*] [**-e** *ENC-MODE*] [**-d** *DEC-MODE*] [*OPTIONS*]

DESCRIPTION
===========

**stenc** manages hardware data encryption on tape devices that support
the SCSI security protocol.

Controlling device encryption
-----------------------------

The encryption mode (what happens to data written to the
device), and decryption mode (what happens to data read from the device)
can be controlled independently. If only one of the following options is
given, the other mode will be inferred to set the encryption and decryption
modes in tandem.

**-e, --encrypt**=\ *ENC-MODE*
   Sets the encryption mode. *ENC-MODE* is either *off* or *on*.

   **off**
      Data written to the device will be not encrypted.

   **on**
      Data written to the device will be encrypted.

**-d, --decrypt**=\ *DEC-MODE*
   Sets the decryption mode. *DEC-MODE* is either *off*, *on*, or *mixed*.

   **off**
      Data read from the device will not be decrypted and only unencrypted
      tape blocks can be read.

   **on**
      Data read from the device will be decrypted and only encrypted tape blocks can
      be read. The drive will only read data it is able to decrypt, and will not
      read unencrypted data on the drive.

   **mixed**
      Data read from the device will be decrypted, if needed. Both encrypted and
      unencrypted tape blocks can be read. The drive will read both encrypted
      data and unencrypted data, provided the drive is able to do so.

Viewing device status
---------------------

When neither options to set encryption or decryption mode are given, **stenc**
prints the encryption settings, the encryption status of the current block,
and capabilities of the device, including a list of supported algorithm indexes.
The device may display current block encryption status as *Unable to determine*
if the tape is positioned at a filemark or end of tape, in which case it may be
necessary to move the tape position using **mt**\ (1).

OPTIONS
=======

**-f, --file**=\ *DEVICE*
   Specifies the device to use (e.g. */dev/nst0*, */dev/nsa0*, */dev/rmt0.1*).
   Use the **lsscsi**\ (8) command on Linux, or **camcontrol**\ (8) on FreeBSD
   to determine the appropriate device to use. It is recommended to the use a
   non-rewinding device (i.e. */dev/nst0* instead of */dev/st0*, */dev/rmt0.1*
   instead of */dev/rmt0*). Typically, only the superuser can access tape
   devices.

   If this option is omitted, and the environment variable **TAPE** is
   set, it is used. Otherwise, a default device defined in the system header
   *mtio.h* is used.

**-a, --algorithm**=\ *index*
   Selects the encryption algorithm to use for the device.
   Changing encryption settings may fail on some devices if this is not a
   supported algorithm for the drive (e.g. HP drives use an algorithm
   index of 1). A list of supported algorithms can be obtained by requesting
   device status. If the device only
   supports one algorithm, this option may be omitted and **stenc** will use
   the only choice. Otherwise **stenc** will print the list of supported algorithms
   and exit if this option is omitted.

**-k, --key-file**=\ *FILE* \| *-*
   Read the encryption key and optional key descriptor from *FILE*, or
   standard input when *FILE* is *-*. If standard input is a terminal,
   this will prompt for the key and optional key
   descriptor. This option is required when *ENC-MODE* and *DEC-MODE*
   are not both *off*. See *KEY INPUT SYNTAX* for the expected format of the
   key file.

**--ckod**
   Clear key on demount. Instructs the device to clear its encryption keys when
   the tape is unloaded instead of keeping it until the drive is power cycled.
   This option may only be given if tape media is presently loaded in the
   device. Some devices may not support this option.

**--allow-raw-read** \| **--no-allow-raw-read**
   Instructs the device to mark encrypted blocks written to the tape to allow
   (or disallow) subsequent raw mode reads. If neither option is given, the
   device default is used, which can be found by requesting the device status.
   Some devices may not support these options.

**-h, --help**
   Print a usage message and exit.

**--version**
   Print version information and exit.

KEY INPUT SYNTAX
================

**stenc** requires that all keys are entered as text hexadecimal strings,
with no delimiters in between bytes. Do not precede your key input with *0x*.
When using a key file, the second line in the file can contain an optional
key descriptor that will be displayed with the device status (see
*KEY DESCRIPTORS*).

Keys can be generated using any cryptographically secure entropy source,
such as the **random**\ (4) device or the **openssl**\ (1SSL) suite of commands.
A 256-bit key file can be created with the following command:

   openssl rand -hex 32

**Example 128 bit key:**

   000102030405060708090a0b0c0d0e0f

**Example 256 bit key:**

   000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f

**Example 256 key file with key descriptor:**

   | 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
   | April backup key

KEY DESCRIPTORS
===============

A key file (see *KEY INPUT SYNTAX*) can optionally include a key descriptor.
The descriptor will be written with each tape block, and will be displayed
when retrieving the drive status, so it should *never* contain information
that would reduce the security of the key (i.e. a checksum or any portion of
the key). If **stenc** detects a tape block is encrypted but it cannot decrypt
the data, the key descriptor of the current block, if any, will be displayed
as part of the device status. This can be useful for determining which key
is used.

KEY CHANGE AUDITING
===================

Each time device encryption settings are changed, **stenc** will write an
entry to the system log. These entries will have a *Key Instance Counter*
corresponding to the counter listed in the device status. Each time the key
is set, the key descriptor, if any, is also written to the log. This allows
you to know when keys were changed and if the key you are using is the same
as a prior key.

EXAMPLE
=======

**stenc -f /dev/nst0 -e on -d on -k /etc/stenc.key**
   Turns on encryption and decryption for */dev/nst0* using the key
   in */etc/stenc.key*

**stenc -f /dev/nst0 -e on -d mixed -k -**
   Asks user to input a key in hexadecimal format and then turns on
   encryption, with mixed decryption mode, for */dev/nst0*

**stenc -f /dev/nst0 -e off -d off**
   Turns off encryption and decryption for */dev/nst0*

**stenc -f /dev/nst0**
   Prints the encryption status of */dev/nst0*

BUGS
====

Report bugs to **https://github.com/scsitape/stenc/issues**

COPYRIGHT
=========

Copyright 2012-2022 contributing authors. License GPLv2: GNU GPL version 2
<http://gnu.org/licenses/gpl.html>. This is free software: you are free
to change and redistribute it. There is NO WARRANTY, to the extent
permitted by law.

SEE ALSO
========

| **openssl**\ (1SSL)
| **mt**\ (1)
| **lsscsi**\ (8)
