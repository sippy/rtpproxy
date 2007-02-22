%define name     rtpproxy
%define ver      0.3
%define rel      1

Name:           %name
Version:        %ver
Release:        %rel%{?dist}
Summary:        A symmetric RTP proxy
Group:          Applications/Internet
License:        BSD
URL:            http://ftp.iptel.org/pub/rtpproxy/
Source0:        http://ftp.iptel.org/pub/rtpproxy/rtpproxy-%{version}.tar.gz
Packager:       Alfred E. Heggestad <aeh@db.org>
Requires(post,preun): chkconfig
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
This is symmetric RTP proxy designed to be used in conjunction with
the SIP Express Router (SER) or any other SIP proxy capable of
rewriting SDP bodies in SIP messages that it processes.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 rpm/rtpproxy.init \
              $RPM_BUILD_ROOT/etc/rc.d/init.d/rtpproxy

%post
if [ "$1" = "1" ]; then
	chkconfig --add %name
fi

%preun
if [ "$1" = "0" ]; then
	service %name stop >/dev/null 2>&1
	/sbin/chkconfig --del %name
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%doc AUTHORS COPYING README 
%attr(755,root,root) %{_bindir}/rtpproxy
%attr(755,root,root) %{_bindir}/makeann
%attr(755,root,root) /etc/rc.d/init.d/*

%changelog
* Tue Jan 30 2007 Alfred E. Heggestad <aeh@db.org> - 0.3.1
- Initial build.

