# Public-only security boundary

This repository and all of its Actions runs are **public**. The workflow builds
only a pinned, publicly disclosed toy C++ program. It must **never** be used to
compile, decrypt, package, test or transmit nonpublic or proprietary source.

## Allowed data

- Public toy program in `src/synthetic_adder.cpp` (checked by SHA-256)
- Numeric operands from -9999 through 9999 and a harmless generated trace ID
- A freshly generated, per-run **public** age recipient (never its secret identity)
- age-encrypted diagnostic artifacts containing synthetic output only

## Barriers

- Only a manually dispatched `main` workflow in this exact public repository
  is accepted, from the approved test dispatcher account.
- No private repository checkout or credentials, SSH keys, GitHub App secrets,
  arbitrary commands, source archives or external payloads.
- An allowlist checks all committed paths. Unexpected files, symlinks,
  oversized files or modifications to toy C++ source fail closed.
- Build runners have read-only Actions tokens. A separate, tightly scoped
  signer may write provenance and request GitHub OIDC identity only. All four
  approved Actions and downloaded crypto binaries are pinned/verified;
  artifact retention is 1 day and no caches are uploaded.
- Compiler and test subprocess stdout/stderr are captured before encryption.
  A random canary and deliberate error check that captured output doesn't
  appear in public logs; the Pi verifies both encrypted reports and run SHA.
- A **separate** attestation-only GitHub-hosted job obtains narrowly scoped
  `id-token: write` and `attestations: write` permissions. Build jobs stay
  read-only. The signer handles only ciphertext, not code, runner secrets or
  Pi decryption keys.
- GitHub OIDC/Sigstore signed attestations bind each ciphertext's SHA-256 digest
  to the specific repository, signer workflow, main ref and source commit.
  The Pi requires verification of all of those conditions before decryption;
  absent, tampered or incorrectly signed artifacts fail closed.
- The Pi downloads only two known artifact names and rejects any extra files,
  missing artifact, incorrect size or unsupported ciphertext format.
- Every dispatch receives a **different** X25519 recipient private key generated
  directly into a sealed Linux memfd. Only that recipient's public key is sent
  to GitHub. The Pi checks the recipient digest inside decrypted run metadata;
  a different run's artifact or key is rejected.

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

## Artifact security properties

- Confidentiality uses age v1 with X25519 ephemeral key agreement,
  ChaCha20-Poly1305 streaming AEAD, and HKDF-SHA-256. Its file key is randomly
  generated for every artifact. No passwords or public Actions secrets are used.
- Modified, truncated, or incorrectly keyed ciphertext fails authenticated
  decryption. The `age` public recipient is **not** a sender signature: anyone
  with it can encrypt arbitrary plaintext.
- Signed Sigstore build provenance adds *sender/workflow identity*, not secrecy.
  A compromised trusted workflow could still attest malicious output. Signed
  provenance also cannot prevent the hosted runner from reading toy source.
- Ciphertext ZIP artifacts and signed provenance are publicly retrievable.
  Their 1-day retention is for data minimization, **not** confidentiality.
- Each run's private identity lives in anonymous Pi kernel memory, which is
  closed after the dispatcher exits. Old ciphertext cannot be read with a
  later run's key. Interrupting the Pi dispatcher irrecoverably loses the key.
  Do not claim cryptographic forward secrecy against an attacker with live Pi
  access: kernel memory, swap, process debugging and crash dumps remain risks.
  Older **synthetic-only** test runs used a persistent identity that has no role
  in the newer per-run protocol.
