# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : packaging/rpm/rsd-master.spec
# Purpose : RPM of the master (Fedora, openSUSE): Python code on the distribution packages + units
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
# Built by scripts/rsd-build-rpm.sh (rsd_version from VERSION, rsd_stage = staged files). The
# python3dist() requirements are resolved by dnf and zypper to the distribution packages.
%global debug_package %{nil}
# Fixed paths (the build host may lack the systemd RPM macros, e.g. rpmbuild on Debian).
%global _unitdir /usr/lib/systemd/system
%global _sharedstatedir /var/lib
%global __os_install_post %{nil}

Name:           rsd-master
Version:        %{rsd_version}
Release:        1
Summary:        Remote Shutdown master - LAN parental control console
License:        0BSD
URL:            https://github.com/tgayet/remote-shutdown
BuildArch:      noarch
Requires:       python3 >= 3.10
Requires:       python3dist(fastapi)
Requires:       python3dist(uvicorn)
Requires:       python3dist(cryptography) >= 3.4
Requires:       python3dist(bcrypt)
Requires:       python3dist(pyjwt)
Requires:       systemd
# File dependencies: "shadow-utils" on Fedora/RHEL, "shadow" on openSUSE.
Requires(pre):  /usr/sbin/useradd
Requires(pre):  /usr/sbin/groupadd

%description
Central service of Remote Shutdown: HTTPS web console (machines UP/DOWN, uptime, IP/MAC,
shutdown, popup, chat, uptime limits), mutual-TLS agent hub, local certificate authority with
automatic agent enrollment, UDP discovery, hash-chained audit log, daily backups.

%install
cp -a %{rsd_stage}/. %{buildroot}/

%pre
getent group rsd-master >/dev/null || groupadd -r rsd-master
getent passwd rsd-master >/dev/null || \
  useradd -r -g rsd-master -d /var/lib/rsd-master -s /sbin/nologin -c "Remote Shutdown master" rsd-master
exit 0

%post
python3 -m compileall -q /usr/lib/rsd-master >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -eq 1 ]; then
  systemctl enable rsd-master.service rsd-master-backup.timer >/dev/null 2>&1 || :
fi
systemctl restart rsd-master.service >/dev/null 2>&1 || :
systemctl start rsd-master-backup.timer >/dev/null 2>&1 || :
cat <<'MSG'
Remote Shutdown master installed.
  Web console : https://<this-host>:8443/   (first login: admin / admin, change it at once)
  Firewall    : firewall-cmd --permanent --add-port=8443/tcp --add-port=8444/tcp --add-port=50000/udp
  CLI         : sudo rsd-master info | status | create-token | backup | reset-password
MSG

%preun
if [ "$1" -eq 0 ]; then
  systemctl disable --now rsd-master-backup.timer rsd-master.service >/dev/null 2>&1 || :
  find /usr/lib/rsd-master -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :

%files
%license %{_docdir}/rsd-master/LICENSE
%doc %{_docdir}/rsd-master/README.md
/usr/lib/rsd-master
%attr(0755,root,root) %{_bindir}/rsd-master
%{_unitdir}/rsd-master.service
%{_unitdir}/rsd-master-backup.service
%{_unitdir}/rsd-master-backup.timer
%dir %{_sysconfdir}/rsd-master
%config(noreplace) %attr(0640,root,rsd-master) %{_sysconfdir}/rsd-master/master.ini
%dir %attr(0750,rsd-master,rsd-master) %{_sharedstatedir}/rsd-master
