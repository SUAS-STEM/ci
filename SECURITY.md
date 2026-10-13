# Public-only security boundary

This repository and all of its Actions runs are **public**. The workflow builds
only a pinned, publicly disclosed toy C++ program. It must **never** be used to
compile, decrypt, package, test or transmit nonpublic or proprietary source.

## Allowed data

- Public toy program in `src/synthetic_adder.cpp` (checked by SHA-256)
- Numeric operands from -9999 through 9999 and a harmless generated trace ID
- Pi's **public** age recipient (never its secret identity)
- age-encrypted diagnostic artifacts containing synthetic output only

## Barriers

- Only a manually dispatched `main` workflow in this exact public repository
  is accepted, from the approved test dispatcher account.
- No private repository checkout or credentials, SSH keys, GitHub App secrets,
  arbitrary commands, source archives or external payloads.
- An allowlist checks all committed paths. Unexpected files, symlinks,
  oversized files or modifications to toy C++ source fail closed.
- No privileged Actions token. Third-party Actions and crypto tools are pinned;
  artifact retention is 1 day and no caches are uploaded.
- Compiler and test subprocess stdout/stderr are captured before encryption.
  A random canary and deliberate error check that captured output doesn't
  appear in public logs; the Pi verifies both encrypted reports and run SHA.

## What encryption **does not** protect

Actions metadata, runner bootstrapping, unexpected stderr from tools executed
outside the capture wrapper, branch changes, files supplied to the runner,
dependencies and network exfiltration are outside log encryption. A malicious
actor with write access can alter the workflow or public code. The runner may
read any plaintext source delivered to it. No public GitHub-hosted workflow is
a confidentiality boundary for proprietary code.

The Pi's personal GitHub CLI currently has broad permissions: never expose it
to GitHub-hosted workflows. For unattended CI, replace that credential with a
fine-grained identity scoped exclusively to this public toy test repository.

GitHub's Actions Terms also restrict unrelated private build workloads on
GitHub-hosted runners in public repositories. If private software must actually
be built, use trusted isolated compute with private logs; a public web-visible
dashboard may safely display coarse non-sensitive status only.
