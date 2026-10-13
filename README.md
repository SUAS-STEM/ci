# CI Relay Lab (public, synthetic only)

Public CI experiment for a **public toy C++ project**. A Raspberry Pi can trigger a
Windows/Linux matrix and retrieve outcomes and **encrypted diagnostic logs** through the GitHub CLI. The
repository contains the entire source project being compiled. **No private
repositories are accessed or forwarded.**

This is intentionally *not* a free-minutes bridge for private GCS builds. GitHub's
Actions Terms prohibit GitHub-hosted runner workloads unrelated to the software
project in the public repository.

## Synthetic end-to-end test on the Pi

With an authenticated `gh` CLI that has permission to trigger workflows in this
repository, run:

```sh
python3 tools/install_age.py
python3 tools/pi_fixture_dispatch.py --left 17 --right -3 --show-logs
```

The script triggers a workflow, finds the exact trace ID, waits for both Windows
and Linux, retrieves the GitHub run/job conclusions and ciphertext artifacts,
and decrypts them **only on the Pi** with age. `--show-logs` optionally prints
decrypted output locally on the Pi. It verifies each runner's synthetic random
canary is absent from publicly visible GitHub logs. It records a small status file in
`.ci-relay-lab-last-run.json` (gitignored). GitHub-hosted workflows never receive
Pi credentials, private source, private build artifacts, or unreviewed scripts.

## Encryption key

**Every run gets a new public/private age keypair.** The Pi runs `age-keygen`
directly into a sealed Linux anonymous `memfd` (no named private-key file and
no Python plaintext copy of the private key). Only the corresponding *public*
recipient travels to GitHub as a workflow input. Two CI workers encrypt their
independent output artifacts to the same one-run recipient. On the Pi, the
private key's descriptor is inherited by only the `age` decryption subprocess;
its memory pages are locked against swap, and the Pi disables ordinary process
inspection and core dumps. The descriptor is closed after verification.
Previous artifacts cannot be decrypted after
that key is discarded. **If the dispatcher process dies, that run's logs are
permanently unavailable; restart a fresh run.**

The previous test's legacy persistent age identity exists only on the Pi for
historical synthetic artifacts; the current protocol never reads it.
Privileged kernel/root access and compromised processes remain threats; this
is not hardware-backed key protection.

The runner executes fixed, public C++ build/test commands with subprocess
stdout/stderr captured in memory, then encrypts that stream with age. Even a
deliberate failed test (exit 47) and randomized canary remain in ciphertext.
Build/test subprocesses receive a sanitized environment that excludes
runner tokens and credential-like variables while preserving compiler discovery
metadata needed by Windows CMake. This filter is defense in depth, not isolation.
After upload, the Pi downloads each platform's artifact and decrypts locally.
An independent attestation-only job signs a SHA-256 hash of each encrypted file
using GitHub's short-lived OIDC/Sigstore identity. The Pi verifies each signed
artifact against the expected GitHub repository, workflow, branch and exact
commit **before** it decrypts anything. The build jobs retain read-only
permissions; only the separate signing job has attestation permissions.
The Pi also verifies each downloaded ZIP's exact GitHub-published SHA-256
before inspecting its single expected ciphertext file. No arbitrary archive
filenames are extracted into the filesystem.
GitHub still exposes job names, run status, workflow metadata and any output
produced *outside* that capture wrapper. This proves the test wrapper works;
it does **not** turn a public repository into secure private-build infrastructure.

## Security boundary

- Workflow inputs are a random trace ID and two constrained integers; no files,
  arbitrary commands, source archives, repository identifiers, or secrets. A
  one-run **public** age recipient is also sent for encrypted logs.
- The compiled program is tracked **in this public repository**. Dispatch cannot
  change which code is compiled.
- Build workflow tokens have read-only contents permissions; the dedicated
  signing job has tightly scoped attestations/OIDC permissions. Checkout
  doesn't persist credentials, and there are no repository secrets or caches.
- The GitHub CLI authentication remains on the Pi. Whoever controls that account
  could still trigger workflows or edit the public repository; use a minimally
  privileged fine-grained token or GitHub App for any future unattended use.
- The Pi checks that local HEAD, remote `main`, and actual workflow run commit
  all match. It rejects mismatched runs and verifies encrypted report metadata
  contains the exact run ID, platform, commit **and one-run recipient digest**
  before accepting diagnostics. Artifacts cannot be replayed between runs.
- Only the four SHA-pinned GitHub actions in these workflows are permitted by
  the repository Actions policy. Action SHA pinning is required in GitHub settings.
- Secret scanning and push protection are enabled for this public repository.
- The trigger is manual; no runner registration, polling daemon, systemd unit,
  webhook listener, GCS branch hook, or private CI workflow is installed.
- GitHub runner/service output and metadata remain **public**; only the captured
  subprocess diagnostics are encrypted. Anyone can download ciphertext artifacts.
  Never pass confidential source/data, even when encrypting captured logs.

## Local checks

```sh
python3 -m unittest discover -s tests -v
cmake -S . -B build && cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```
