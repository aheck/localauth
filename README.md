# LocalAuth

C++20 header-only challenge-response authentication using ACL-protected files.
No networking code. Uses SHA-256/HMAC-SHA-256 implemented in the header.

## Example

```cpp
#include "LocalAuth.h"
LocalAuth::AuthServer server;
if (!server.setAllowedUsers({"alice", "bob"})) {
    // Invalid account configuration: the server now denies everyone.
    return;
}
auto challenge = server.createChallenge("alice");
// Send challenge.id(), challenge.filePath(), challenge.nonce() over your transport.
// Client: 
LocalAuth::AuthClient client;
// Required when the server runs under a different OS account:
if (!client.setTrustedServer("server-account")) return;
// Obtain this account name from trusted configuration, not the network.
auto response = client.createResponse(challenge.id(), challenge.filePath(), challenge.nonce());
// Send response.digest() back over your transport.
auto result = server.verifyResponse(challenge.id(), response.digest());
```

Configure both sides with `setChallengeDirectory(path)`; defaults are `/tmp` on Linux/macOS and the Windows directory's `Temp` child on Windows.
`allowAllUsers()` is the default; `setAllowedUsers({})` denies everyone.
`setAllowedUsers` resolves names to UIDs/SIDs immediately and returns `false` if
any name cannot be resolved, leaving an empty allowlist. Aliases resolve to the
same identity. Account names containing NULs are rejected. Reconfigure after
account changes; IDs may be reused by the OS after account deletion.

Clients trust their own effective UID/process SID by default. For a server under
a different account, call `setTrustedServer(name)` using trusted application
configuration. Failure clears the trusted identity and prevents responses.
Client configuration must be completed before concurrent calls to `createResponse`.
Server operations are serialized internally; changing the allowlist affects new
challenges, while already issued challenges remain valid until consumed or expired.

## Build

Install Meson 1.1 or newer, Ninja, and a C++20 compiler (GCC, Clang/Apple
Clang, or MSVC with the Windows SDK). From the repository root:

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

On Windows, use a Visual Studio developer shell, or use
`meson setup build --vsenv` to activate the installed Visual Studio environment.
Meson supplies the include path, thread dependency, and Windows `bcrypt` and
`advapi32` libraries. macOS uses the SDK's ACL/membership APIs; Linux does not
require libacl.

The `crypto`, `authentication`, `hardening`, and `lifecycle` suites run on all
three platforms, including in release builds. They cover crypto padding/block
boundaries, malformed files and responses, restrictive ACLs, trusted ownership,
replay, expiration, cleanup, and concurrent authentication. POSIX tests also
reject symlinks and FIFOs; all platforms reject hard links and directories.
Tests require a temporary filesystem with ACL and hard-link support.

The `cross-account` suite runs on Linux/macOS as root, then drops a child process
to `nobody`. It tests allowed reads, OS denial for an unrelated challenge,
untrusted ownership, and full challenge/response verification. Ordinary Meson
runs skip this suite with exit code 77 when privileges are unavailable. CI runs
it separately with `sudo ./build/localauth-tests cross-account`. Windows currently
skips this suite; its other suites exercise DACL validation under the current
account. Native Windows/macOS results must be verified by CI.

For use as a Meson subproject, configure with `-Dlocalauth:tests=false` and use
`dependency('localauth', fallback: ['localauth', 'localauth_dep'])` in the parent
project. The consuming project must also enable C++20.

## Hardening behavior

- File ownership, type, length, link count, and ACL are checked on the opened
  handle before reading. Only the generated restrictive ACL shape is accepted;
  broader or merely equivalent custom ACLs are intentionally rejected. The file
  name must match the challenge ID.
- Windows files use a protected DACL to exclude inherited permissions. macOS
  grants the reader data and ACL-read access. Linux ACL xattrs use explicit
  little-endian encoding without a libacl dependency.
- Scope guards close native handles and free ACL allocations on early returns
  and exceptions. Secret buffers, HMAC pads, and SHA working buffers use secure
  erase on destruction (`SecureZeroMemory`, `memset_s`, or `explicit_bzero`).
- `AuthChallenge::systemError()` preserves filesystem/creation error details;
  `errorString()` includes that diagnostic. Creation retries only filename
  collisions. Failed registration removes the newly created file.

## Security / limitations

- This authenticates the ability to read a user-restricted file, **not the peer process's UID/SID**.
- The caller must bind the challenge to the initiating TCP connection. HMAC does **not** encrypt or authenticate subsequent traffic, nor prevent active relay attacks.
- The client must trust the server and its configured challenge directory. A malicious server could trick a client into HMAC-signing an attacker-chosen secret; this protocol is not mutual authentication.
- Linux requires a filesystem supporting `system.posix_acl_access`; macOS requires extended ACL support. Some mount options and filesystem types will fail.
- `C:\Windows\Temp` may not permit unprivileged file creation on every installation. Directory paths are configurable.
- The directory must be reachable by the target user; the server must be able to create files there. Other principals with elevated privileges may still read files.
- Configure a directory and parent directories that untrusted principals cannot rename or replace. Canonical path checks do not pin parent directory handles. On POSIX, use a server-owned directory or an appropriate sticky directory. File ownership/ACL checks cannot distinguish a malicious process running as the trusted owner, and do not provide mutual authentication.
- The file remains on disk until verified, canceled, expired (on a server operation), or the server object is destroyed. A crash can leave orphan files.
- Secure erase covers owned buffers; it does not guarantee removal of register spills, OS copies, swap, crash dumps, or data remaining on storage.
- Linux tests have been run locally; Windows and macOS require native validation
  through the included CI workflow or a local build on those systems.
