# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : packaging/rpm/rsd-agent.spec
# Purpose : RPM of the agent (Fedora, RHEL / Rocky / AlmaLinux, openSUSE): static binary + systemd unit
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
# Built by scripts/rsd-build-rpm.sh, which defines rsd_version (from VERSION) and rsd_stage
# (staged files). The binary is static (CGO disabled): no runtime dependency, no Go needed.
%global debug_package %{nil}
# Fixed paths (the build host may lack the systemd RPM macros, e.g. rpmbuild on Debian).
%global _unitdir /usr/lib/systemd/system
%global _sharedstatedir /var/lib
%global __os_install_post %{nil}

Name:           rsd-agent
Version:        %{rsd_version}
Release:        1
Summary:        Remote Shutdown agent - remote shutdown, popups and chat
License:        0BSD
URL:            https://github.com/tgayet/remote-shutdown
Requires:       systemd
Recommends:     zenity

%description
Agent of Remote Shutdown. It enrolls once with the master (one-time token and pinned CA
fingerprint), then keeps a mutual-TLS connection open to receive shutdown orders with countdown,
popup messages and chat messages, shown in the language and theme of the desktop user, and
reports its uptime and network interfaces. Static binary, no runtime dependency.

%install
cp -a %{rsd_stage}/. %{buildroot}/

%post
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -eq 1 ]; then
  systemctl enable rsd-agent.service >/dev/null 2>&1 || :
fi
systemctl restart rsd-agent.service >/dev/null 2>&1 || :
if [ ! -f /var/lib/rsd-agent/client.crt ]; then
  echo "Remote Shutdown agent installed but not enrolled: run the command shown by the web console,"
  echo "  sudo rsd-agent enroll --token <TOKEN> --fingerprint <CA-FINGERPRINT> --master <MASTER-IP>"
fi

%preun
if [ "$1" -eq 0 ]; then
  systemctl disable --now rsd-agent.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -eq 0 ]; then
  rm -rf /var/lib/rsd-agent
fi

%files
%license %{_docdir}/rsd-agent/LICENSE
%doc %{_docdir}/rsd-agent/README.md
%attr(0755,root,root) %{_bindir}/rsd-agent
%{_unitdir}/rsd-agent.service
%dir %attr(0700,root,root) %{_sysconfdir}/rsd-agent
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/rsd-agent/agent.json
%dir %attr(0700,root,root) %{_sharedstatedir}/rsd-agent
