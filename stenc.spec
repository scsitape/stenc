# SPDX-FileCopyrightText: 2022 stenc authors
#
# SPDX-License-Identifier: GPL-2.0-or-later

Name:           stenc
Version:        2.x.x
Release:        1%{?dist}
Summary:        SCSI Tape Encryption Manager

License:        GPL-2.0-or-later
URL:            https://github.com/scsitape/stenc
Source0:        https://github.com/scsitape/stenc/archive/%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  bash-completion

%description
SCSI Tape Encryption Manager - Manages encryption on LTO 4 and newer tape
drives with hardware-based encryption

%prep
%autosetup

%build
./autogen.sh
%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%files
%license LICENSES/GPL-2.0-or-later.txt
%doc README.md AUTHORS.md
%{_bindir}/stenc
%{_mandir}/man1/stenc.1*
%{_datadir}/bash-completion/completions/stenc

%changelog
* Sat Aug 27 2022 Paweł Marciniak <sunwire+repo@gmail.com> - 2.x.x-1
- Version 2.0.0 Pre-release

