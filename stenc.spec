# SPDX-FileCopyrightText: 2022 stenc authors
#
# SPDX-License-Identifier: GPL-2.0-or-later

Name:           stenc
Version:        1.1.1
Release:        3%{?dist}
Summary:        SCSI Tape Encryption Manager

License:        GPLv2
URL:            https://github.com/scsitape/stenc
Source0:        https://github.com/scsitape/stenc/archive/%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  autoconf
BuildRequires:  automake

%description
SCSI Tape Encryption Manager - Manages encryption on LTO 4 and newer tape
drives with hardware-based encryption

%prep
%setup -q

%build
./autogen.sh
%configure
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%license COPYING
%doc README.md AUTHORS
%{_bindir}/stenc
%{_mandir}/man1/stenc.1*



%changelog
* Wed Nov 11 2020 Paweł Marciniak <sunwire+repo@gmail.com> - 1.0.8-3
- Remove BuildRoot tag, add smp flags to make and license macro

* Sat Nov 07 2020 Paweł Marciniak <sunwire+repo@gmail.com> - 1.0.8-2
- Make will no longer be in BuildRoot by default

* Sat Jul 4 2020 Paweł Marciniak <sunwire+repo@gmail.com> 1.0.8-1
- Initial SPEC file
