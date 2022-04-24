[![Total alerts](https://img.shields.io/lgtm/alerts/g/scsitape/stenc.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/scsitape/stenc/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/scsitape/stenc.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/scsitape/stenc/context:cpp)

Stenc
-----

SCSI Tape Encryption Manager - Manages encryption on LTO tape drives (starting with generation 4) with hardware-based encryption. 
Program should work on any other SCSI security protocol (SSP) capable tape drives. Built specifically for Linux and AIX. 
Supports key change auditing and key descriptors (uKAD). 

Features
--------

* SCSI hardware-based encryption management
* Supports AIX and Linux
* Supports most SSP compliant devices, such as LTO-4 tape drives
* Random key generation
* Key change audit logging
* AES Encryption
* Key Descriptor Management

Get the source code and compile
-------------------------------

```
git clone git@github.com:scsitape/stenc.git
cd stenc/
autoreconf --install
autogen.sh && ./configure  
make check     # optionally run the catch testing framework
make
```

Linux Packages
--------------
[![Packaging status](https://repology.org/badge/vertical-allrepos/stenc.svg)](https://repology.org/metapackage/stenc)


License
-------
Program copyright 2012-2018 contributing authors.

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
