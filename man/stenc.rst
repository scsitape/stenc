NAME
====


stenc - SCSI Tape Hardware Encryption Manager


SYNOPSIS
========

| **stenc** **-g** *length* **-k** *file* [**-kd** *description*]
| **stenc** **-f** *device* [**--detail**]
| **stenc** **-f** *device* **-e** **on**\ \|\ **mixed**\ \|\ **rawread** [**-a** *index*] [**-k** *file*] [**--ckod**] [**--protect** \| **--unprotect**]
| **stenc** **-f** *device* **-e** **off** [**-a** *index*] [**--ckod**] [**--protect** \| **--unprotect**]
| **stenc** **--version**

AVAILABILITY
============

Linux, AIX

DESCRIPTION
===========

Allows you to manage hardware encryption on SSP enabled tape devices
(LTO4, LTO5, etc).

OPTIONS
=======

**-g**\ *length* **-k** **<file to save as>** [**-kd** *<key descriptor(uKAD)>*]
   Generates a key file of *length* (in bits) containing a random
   hexadecimal key. After entering this option, you will be required to
   press random keys followed by the enter key. This will seed the
   random number generator so that your key is more secure. On systems
   with **/dev/random**, the key is automatically generated from the
   random content read from this file. Specify the file to save the key
   into with the -k option (you will need write permissions to that file
   location). Lastly you can enter an optional key description using the
   -kd flag (see *KEY DESCRIPTORS*). This key file can then be used with
   the **-k** option. You should not generate a key file over an
   unsecured remote session. Typically, key files should be set to 256
   bits (32 hexadecimal bytes), however your device may only support 128
   bits.

**-f** *device*
   Specifies the device to use (i.e. */dev/nst0, /dev/rmt0.1,
   /dev/sg0*). Use the **lsscsi** command to determine the appropriate
   device to use. You should always use a device name that does not
   rewind (i.e. use /dev/nst0 instead of /dev/st0, /dev/rmt0.1 instead
   of /dev/rmt0). Use commands like 'cat /proc/scsi/scsi', 'lsscsi', and
   'lsdev' to determine the proper device to use. On some distros, a
   /dev/sg device must be used instead of a /dev/st device.

If this is the only option specified, the status of the device will be
displayed. To retrieve more detailed status information, add
**--detail**. If you are root and the status command fails, either the
*device* is incorrect (try another link to the device: */dev/rmt0.1*,
*/dev/nst0*, */dev/tape*, etc.), a tape may not be in the drive, you may
be using the wrong algorithm for the tape drive (see the **-a** option),
or the device does not support SCSI Security Protocol. **stenc** may
read up to 100 blocks of the tape, starting at the current position, in
order to determine if the volume has been encrypted. For this reason,
you should not run the status command while another process is accessing
the drive. If the device returns *Unable to determine* for the volume
encryption status, you may need to move to a section of the tape that
contains data (i.e. **mt -f <device> fsr <count>**) or rewind the tape
in order for **stenc** to output the volume status.

**-e** **on** \| **mixed** \| **rawread** \| **off** 
   Sets the encryption mode for the device specified with **-f** option.
   Successful operations of this type will create an audit entry in the
   */var/log/stenc* file. If **off** is not specified and the **-k**
   option is not specified, the program will require the user to enter a
   hexadecimal key (see *KEY INPUT SYNTAX*) and an optional key
   description (see *KEY DESCRIPTORS*).

**on** - The drive will encrypt all data sent to it and will only output
data it is able to decrypt, ignoring unencrypted data on the drive.

**mixed** - The drive will encrypt all data sent to it and will output
both encrypted data and unencrypted data, providing the drive is able to
do so.

**rawread** - The drive will encrypt all data sent to it and will output
unencrypted data and raw encrypted data. You will probably need to have
specified **--unprotect** when the data was written in order to read it
with this option. Some drives do not support this option. See the
**--protect** option.

**off** - The drive will neither encrypt data sent to it, or decrypt
encrypted data found on the drive. If this command fails you may have
switch your algorithm or specify a different default key size when you
configure the program

**WARNING:** The SCSI device will revert all encryption settings if the
tape device is power cycled (if the tape drive is extenal, it may keep
the settings even if the system is rebooted). You can modify you local
startup script (/etc/rc.local, /etc/rc, etc.) to set encryption at
reboot if need be. If you do this, you will need to use the **-k**
option to prevent the system from waiting on the local console user to
enter the encryption key.

**-a** *index*
   Only valid when setting encryption (see the **-e** option). Specifies
   the algorithm index to use for the device (defaults to 0, which can
   be changed using the --with-default-algorithm configure option).
   Setting encryption on/off may fail on some devices if this is not the
   correct algorithm for the drive (i.e. HP drives use an algorithm
   index of 1).

**--ckod**
   Only valid when setting encryption (see the **-e** option). Instructs
   the drive to clear its encryption keys when the volume is unmounted
   instead of keeping it until the drive is power cycled. Some devices
   may not support this option.

**--protect** \| **--unprotect**
   Only valid when setting encryption (see the **-e** option). Instructs
   the drive to **protect** or **unprotect** any encrypted data from
   being raw read. See the **-e rawread** option. Some devices may not
   support these options.

**-k** *file*
   Only valid when turning encryption on (see the **-e** option) or
   generating a new key (see the **-g** option). When turning encryption
   on, this specifies the location of a key file previously generated
   with the **-g** option. When generating a new key with the **-g**
   option, this specifies the key file that the new key will be saved
   into. Key files should be owned by root ('**chown root**') and only
   readable by root ('**chmod 600**'). **stenc** automatically chmods
   key files generated with the **-g** option.

KEY INPUT SYNTAX
================

All keys should be a maximum of 256 bits (32 bytes). **stenc** requires that all keys are entered using 2 digit hexadecimal bytes, with no delimiters in between bytes. Do not precede your key input with '0x'. If you try to use a key size that the drive does not support, the command will error. When using a key file, the second line in the file can contain an optional key description that will be displayed with the device status (see the **-f** option).

**Example 128 bit Key:**
   000102030405060708090a0b0c0d0e0f

**Example 256 bit Key:**
   000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f

EXAMPLE
=======

**stenc -g 256 -k /etc/tape.key -kd "September Tape Key"** 
   Generate a random 256 bit key file with the description "September
   Tape Key" and save it into /etc/tape.key

**stenc -f /dev/st0 -e on -k /etc/stenc.key**
   Turns on encryption on /dev/st0 using the key contained in
   /etc/stenc.key

**stenc -f /dev/st0 -e on**
   Asks user to input a key in hexadecimal format and then turns on
   encryption for /dev/st0 using that key

**stenc -f /dev/st0 -e off**
   Turns off encryption for /dev/st0

**stenc -f /dev/st0 --detail**
   Outputs the detailed encryption status of /dev/st0

**tail /var/log/stenc**
   Lists the last few key change audit entries

KEY CHANGE AUDITING
===================

Each time a key is changed using this program, a corresponding entry
will be entered into the */var/log/stenc* file. These entries will have
an *Key Instance Counter* corresponding to the counter listed in the
device status (see the **-f** option). Each time the key is set, a
checksum of that key (or a key description) is also listed in this file.
This allows you to know when keys were changed and if the key you are
using is the same as a prior key. If an unauthorized party would
compromise this log file, your key security would be decreased if
checksums were present in the log. To prevent this, you should use key
descriptors instead of checksums (see *KEY DESCRIPTORS*).

KEY DESCRIPTORS
===============

Key descriptors are set when using the **-g** option or the **-e**
option. They will be displayed when retrieving the drive status (see the
**-f** option). These descriptors will be written to the volume, so they
should NEVER contain information that would reduce the security of the
key (i.e. a checksum, bitlength, algorithm, a portion of the key). If
**stenc** detects that the volume is encrypted but it cannot decrypt the
data, the key descriptor on the volume will be displayed as part of the
device status. This can be useful for determining which key goes to
which volume.

REPORTING BUGS
==============

Report **stenc** bugs to https://github.com/scsitape/stenc/issues

PROJECT UPDATES
===============

Visit **https://github.com/scsitape/stenc** for more information.

COPYRIGHT
=========

Copyright 2012-2022 contributing authors. License GPLv2: GNU GPL version 2
<http://gnu.org/licenses/gpl.html>. This is free software: you are free
to change and redistribute it. There is NO WARRANTY, to the extent
permitted by law.

SEE ALSO
========

| **mt**\ (1L)
| **lsscsi**\ (8)