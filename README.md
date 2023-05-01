<!--
SPDX-FileCopyrightText: 2022 stenc authors

SPDX-License-Identifier: GPL-2.0-or-later
-->

[![REUSE status](https://api.reuse.software/badge/github.com/scsitape/stenc/)](https://api.reuse.software/info/github.com/scsitape/stenc/)


Stenc
-----

SCSI Tape Encryption Manager - Manages encryption on LTO tape drives (starting with generation 4) with hardware-based encryption. 
Program should work on any other SCSI security protocol (SSP) capable tape drives. Built specifically for Linux. 
Supports key change auditing and key descriptors (uKAD). 

Features
--------

* SCSI hardware-based encryption management
* Supports Linux 
* Supports most SSP compliant devices, such as LTO-4 tape drives
* Key change audit logging
* AES Encryption
* Key Descriptor Management

Get the source code and compile
-------------------------------

```
git clone https://github.com/scsitape/stenc.git
cd stenc/
autoreconf --install
./autogen.sh && ./configure  
make check     # optionally run the catch testing framework
make
```

Usage example
-------------


```
$ stenc -f /dev/nst0
Status for /dev/nst0 (TANDBERG LTO-6 HH 3579)
--------------------------------------------------
Reading:                         Decrypting (AES-256-GCM-128)
Writing:                         Encrypting (AES-256-GCM-128)
                                 Protecting from raw read
Key instance counter:            1
Drive key desc. (U-KAD):         mykey20170113
Supported algorithms:
1    AES-256-GCM-128
     Key descriptors allowed, maximum 32 bytes
     Raw decryption mode allowed, raw read enabled by default
```


Linux Packages
--------------
[![Packaging status](https://repology.org/badge/vertical-allrepos/stenc.svg)](https://repology.org/metapackage/stenc)


Requirements
------------
AIX support was suspended on 2022-05-08 until we have contributors who can develop and test the code on AIX.


License
-------
Program copyright 2012-2022 contributing authors.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

Further reading
---------------

IBM Tape Library Guide for Open Systems
ISBN-13: 9780738458342
http://www.redbooks.ibm.com/abstracts/sg245946.html?Open


SCSI-Programming-HOWTO
https://tldp.org/HOWTO/archived/SCSI-Programming-HOWTO/SCSI-Programming-HOWTO-9.html 
