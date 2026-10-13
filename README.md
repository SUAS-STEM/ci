# CI Relay Lab (public, synthetic only)

Public CI experiment for a **public toy C++ project**. A Raspberry Pi can trigger a
Windows/Linux matrix and retrieve outcomes and logs through the GitHub CLI. The
repository contains the entire source project being compiled. **No private
repositories are accessed or forwarded.**

This is intentionally *not* a free-minutes bridge for private GCS builds. GitHub's
Actions Terms prohibit GitHub-hosted runner workloads unrelated to the software
project in the public repository.

## Synthetic end-to-end test on the Pi

With an authenticated `gh` CLI that has permission to trigger workflows in this
repository, run:

```sh
python3 tools/pi_fixture_dispatch.py --left 17 --right -3 --show-logs
```

The script triggers a workflow, finds the exact trace ID, waits for both Windows
and Linux, retrieves the GitHub run/job conclusions, and optionally prints the
public job logs. It records a small local status file in
`.ci-relay-lab-last-run.json` (gitignored). GitHub-hosted workflows never receive
Pi credentials, private source, private build artifacts, or unreviewed scripts.

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
- The trigger is manual; no runner registration, polling daemon, systemd unit,
  webhook listener, GCS branch hook, or private CI workflow is installed.
- Logs and run metadata in this test are **public**; never pass confidential
  data, even if encrypted. Public-repo workflow results are also public.

## Local checks

```sh
python3 -m unittest discover -s tests -v
cmake -S . -B build && cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```
