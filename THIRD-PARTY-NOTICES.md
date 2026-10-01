<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : THIRD-PARTY-NOTICES.md
Purpose : Third-party components and their licenses
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Third-party notices

Remote Shutdown is distributed under the 0BSD license. It uses, without copying their code into
this repository, the following components, which keep their own licenses.

| Component | Used by | License |
|---|---|---|
| [FastAPI](https://github.com/fastapi/fastapi) / [Starlette](https://github.com/encode/starlette) | master | MIT / BSD-3-Clause |
| [uvicorn](https://github.com/encode/uvicorn) | master | BSD-3-Clause |
| [cryptography](https://github.com/pyca/cryptography) | master | Apache-2.0 or BSD-3-Clause |
| [bcrypt](https://github.com/pyca/bcrypt) | master | Apache-2.0 |
| [PyJWT](https://github.com/jpadilla/pyjwt) | master | MIT |
| [Go standard library](https://go.dev) | agent (statically linked) | BSD-3-Clause |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | agent (statically linked) | BSD-3-Clause |
| [msitools / wixl](https://wiki.gnome.org/msitools) | build only (MSI) | LGPL-2.1+ |

The agent binaries embed the Go runtime and `golang.org/x/sys`: their BSD-3-Clause notices apply
to the binary distributions.
