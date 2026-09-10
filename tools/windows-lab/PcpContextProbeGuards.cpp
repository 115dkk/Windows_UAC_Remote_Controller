// SPDX-License-Identifier: GPL-2.0-or-later
// Closed read-only test executable, not a mode of the elevated bootstrap.
// Do not link a payload resource or the bootstrap's requireAdministrator manifest.
// Set asInvoker and System32 dependent-load flags on the actual linker command;
// MSVC ignores these options when supplied through object-file directives.
#define PCP_CONTEXT_READ_ONLY_GUARDS 1
#include "PcpContextProbeBootstrap.cpp"
