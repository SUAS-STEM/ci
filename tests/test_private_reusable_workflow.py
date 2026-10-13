"""Safety and syntax checks for drop-in reusable PRIVATE caller CI definition."""
import re
import subprocess
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/private-reusable-build.yml"


class PrivateReusableWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text("utf-8")

    def test_public_repo_supplies_workflow_only(self):
        self.assertIn("workflow_call:", self.source)
        self.assertNotRegex(self.source, r"(?m)^  (?:push|pull_request|schedule|workflow_dispatch):")
        self.assertIn("github.event.repository.private == true", self.source)
        self.assertIn("github.event.repository.default_branch", self.source)
        self.assertIn("github.repository != 'SUAS-STEM/ci-relay-lab'", self.source)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", self.source)
        self.assertIn("persist-credentials: false", self.source)

    def test_builds_private_caller_not_public_project(self):
        self.assertNotIn("git clone", self.source)
        self.assertNotIn("repository: SUAS-STEM/gcs", self.source)
        self.assertNotIn("repository: SUAS-STEM/ci-relay-lab", self.source)
        self.assertIn("cmake --build build --config Release", self.source)
        self.assertIn("ctest --test-dir build -C Release", self.source)

    def test_no_actions_artifacts_and_scoped_release_secrets(self):
        for forbidden in ("upload-artifact", "download-artifact", "gh run download", "secrets: inherit"):
            self.assertNotIn(forbidden, self.source)
        self.assertIn("vault_release_token:", self.source)
        self.assertIn("release_repository:", self.source)
        self.assertIn('if [[ "$(gh api "repos/$REPO" --jq .private)" != "true" ]]', self.source)
        self.assertIn('[[ "$REPO" != "$GITHUB_REPOSITORY" && -z "$VAULT_TOKEN" ]]', self.source)
        self.assertIn("--draft --latest=false", self.source)

    def test_configurable_trusted_runner_labels(self):
        for label in ("linux_runner", "windows_runner"):
            self.assertIn(label + ":", self.source)
            self.assertIn("${{ inputs." + label + " }}", self.source)

    def test_publish_only_after_both_platforms_pass(self):
        self.assertIn('BUILD_RESULT: ${{ needs.build.result }}', self.source)
        self.assertIn('if [[ "$BUILD_RESULT" != "success" ]]', self.source)
        self.assertIn("both private Windows/Linux executables", self.source)
        self.assertIn('gh release edit "$TAG" --repo "$REPO" --draft=false', self.source)
        self.assertIn('gh release delete "$TAG" --repo "$REPO" --cleanup-tag --yes', self.source)
        self.assertIn('if [[ "$BODY" != "$EXPECTED" || "$DRAFT" != "true" ]]', self.source)

    def test_embedded_bash_syntax(self):
        lines = self.source.splitlines()
        blocks = []
        current = None
        for line in lines:
            if re.match(r"^        run: \|$", line):
                if current is not None:
                    blocks.append(current)
                current = []
            elif current is not None:
                if line.startswith("          "):
                    current.append(line[10:])
                elif not line.strip():
                    current.append("")
                else:
                    blocks.append(current)
                    current = None
        if current is not None:
            blocks.append(current)
        self.assertGreaterEqual(len(blocks), 4)
        for block in blocks:
            checked = subprocess.run(["bash", "-n"], input="\n".join(block) + "\n",
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
