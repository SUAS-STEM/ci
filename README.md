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

The public recipient key is `keys/pi-logs.agepub`, and the Pi-only identity is
`/home/pi/.config/ci-relay-lab/identity.txt` (`0600`). The key was generated on
the Pi with `age-keygen`; **the private identity is never copied to GitHub**.
To create a new key for a new deployment, generate an age identity directly on
the recipient host and commit only its public recipient key. Protect and back up
the private key through an appropriate encrypted private mechanism; losing it
means existing encrypted artifacts cannot be decrypted.

The runner executes fixed, public C++ build/test commands with subprocess
stdout/stderr captured in memory, then encrypts that stream with age. Even a
deliberate failed test (exit 47) and randomized canary remain in ciphertext.
Build/test subprocesses receive a minimal allowlisted environment, excluding
the runner's `GITHUB_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, and unrelated variables.
After upload, the Pi downloads each platform's artifact and decrypts locally.
GitHub still exposes job names, run status, workflow metadata and any output
produced *outside* that capture wrapper. This proves the test wrapper works;
it does **not** turn a public repository into secure private-build infrastructure.

## Security boundary

- Workflow inputs are a random trace ID and two constrained integers; no files,
  arbitrary commands, source archives, repository identifiers, or secrets.
- The compiled program is tracked **in this public repository**. Dispatch cannot
  change which code is compiled.
- Workflow token has read-only contents permissions, checkout doesn't persist it,
  there are no repository secrets or public Actions artifacts/caches to expose.
- The GitHub CLI authentication remains on the Pi. Whoever controls that account
  could still trigger workflows or edit the public repository; use a minimally
  privileged fine-grained token or GitHub App for any future unattended use.
- The Pi checks that local HEAD, remote `main`, and actual workflow run commit
  all match. It rejects mismatched runs and verifies encrypted report metadata
  contains the exact run ID, platform and commit before accepting diagnostics.
- Only the two SHA-pinned GitHub actions in this workflow are permitted by the
  repository Actions policy. Action SHA pinning is required in GitHub settings.
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
