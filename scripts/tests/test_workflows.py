from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'


class WorkflowContractTests(unittest.TestCase):
    def test_build_and_ci_use_the_repository_toolchain(self) -> None:
        version = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
        dockerfile = (ROOT / 'Dockerfile').read_text()
        workflow = (WORKFLOWS / 'test.yml').read_text()
        self.assertEqual(re.findall(r'^ARG RUST_VERSION=(\S+)$', dockerfile, re.MULTILINE), [version])
        self.assertEqual(re.findall(r'^\s*RUST_TOOLCHAIN_VERSION: "([^"]+)"$', workflow, re.MULTILINE), [version])

    def test_external_actions_are_pinned_to_immutable_commits(self) -> None:
        files = list(WORKFLOWS.glob('*.yml'))
        self.assertGreaterEqual(len(files), 2)
        for path in files:
            workflow = path.read_text(encoding='utf-8')
            refs = re.findall(r'^\s*-?\s*uses:\s+([^#\s]+)', workflow, re.MULTILINE)
            for action_ref in refs:
                if action_ref.startswith('./'):
                    self.assertTrue((ROOT / action_ref).is_file())
                else:
                    self.assertRegex(action_ref, r'^[\w-]+/[\w-]+@[0-9a-f]{40}$')
            self.assertNotIn('persist-credentials: true', workflow)
            self.assertEqual(workflow.count('actions/checkout@'), workflow.count('persist-credentials: false'))

    def test_pull_requests_cannot_publish_or_access_registry_credentials(self) -> None:
        workflow = (WORKFLOWS / 'build.yml').read_text(encoding='utf-8')
        before_publish, publish = workflow.split('\n  publish:\n')
        self.assertIn('  pull_request:', before_publish)
        self.assertIn('permissions:\n  contents: read\n', before_publish)
        self.assertNotIn('packages: write', before_publish)
        self.assertNotIn('secrets.', before_publish)
        self.assertNotIn('pull_request_target', workflow)
        self.assertIn('    needs: [test, image]', publish)
        self.assertIn("if: github.event_name == 'push' && github.repository == 'chrisbennight/mcp-unifi-rs'", publish)
        self.assertIn('      packages: write', publish)
        self.assertIn('secrets.GITHUB_TOKEN', publish)
        self.assertIn('--password-stdin', publish)
        self.assertLess(publish.index('Validate publication tags'), publish.index('docker login'))

    def test_publishes_the_tested_artifact_from_the_same_run(self) -> None:
        workflow = (WORKFLOWS / 'build.yml').read_text(encoding='utf-8')
        self.assertIn('python3 scripts/smoke_image.py', workflow)
        self.assertIn('--tag "${IMAGE}:sha-${GITHUB_SHA}"', workflow)
        self.assertIn('python3 scripts/smoke_image.py "${IMAGE}:sha-${GITHUB_SHA}"', workflow)
        self.assertLess(workflow.index('Smoke both runtime surfaces'), workflow.index('docker save'))
        publish = workflow.split('\n  publish:\n')[1]
        self.assertIn('name: tested-image', publish)
        self.assertIn('digest-mismatch: error', publish)
        self.assertNotIn('run-id:', publish)
        self.assertNotIn('github-token:', publish)
        self.assertNotIn('docker build', publish)
        self.assertIn('test "$revision" = "$GITHUB_SHA"', publish)
        self.assertLess(publish.index('test "$revision"'), publish.index('docker login'))

    def test_github_builds_need_no_lab_service(self) -> None:
        for path in WORKFLOWS.glob('*.yml'):
            workflow = path.read_text(encoding='utf-8')
            for private_dependency in ('cacahuate.org', 'infisical', 'CRATES_INDEX_URL', 'self-hosted', 'renovate-threat-gate'):
                self.assertNotIn(private_dependency, workflow)
        cargo_config = (ROOT / '.cargo/config.toml').read_text(encoding='utf-8')
        self.assertNotIn('replace-with', cargo_config)

    def test_source_checks_and_manifest_emission_are_gated(self) -> None:
        workflow = (WORKFLOWS / 'test.yml').read_text(encoding='utf-8')
        self.assertIn('  workflow_call:', workflow)
        for command in (
            'cargo fmt --all -- --check',
            'cargo clippy --workspace --all-targets --all-features --locked -- -D warnings',
            'cargo test --workspace --all-features --locked',
            'cargo doc --workspace --no-deps --locked',
            'python3 scripts/check_docs.py',
            'python3 -m unittest discover -s scripts/tests',
            '--emit-gateway-manifest',
            'classification_mode: mcp_annotations',
            'bearer_env: MCP_GATEWAY_UPSTREAM_BEARER_UNIFI',
            'isolation: per_call',
        ):
            self.assertIn(command, workflow)

    def test_security_tools_are_pinned_isolated_and_scan_before_publication(self) -> None:
        workflow = (WORKFLOWS / 'build.yml').read_text(encoding='utf-8')
        image = workflow.split('\n  publish:\n')[0]
        for tool in ('GITLEAKS', 'SYFT'):
            self.assertRegex(image, rf'{tool}_IMAGE: [\w./-]+:v[\d.]+@sha256:[a-f0-9]{{64}}')
        self.assertIn('git archive HEAD', image)
        self.assertIn('--redact=100', image)
        self.assertIn('scripts/check_build_context.py', image)
        self.assertEqual(image.count('docker run '), 3)
        self.assertEqual(image.count('--network none --read-only --cap-drop ALL'), 3)
        self.assertEqual(image.count('--user "$(id -u):$(id -g)"'), 2)
        self.assertEqual(image.count('--tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777'), 2)
        self.assertNotIn('docker.sock', workflow)
        self.assertIn('scan docker-archive:/image.tar', image)
        self.assertIn('scan dir:/scan', image)
        self.assertIn('name: software-inventory', image)
        self.assertLess(image.index('Scan tracked source'), image.index('Build image'))
        self.assertLess(image.index('Smoke both runtime surfaces'), image.index('Inventory source'))

    def test_image_and_executable_use_the_github_project_name(self) -> None:
        package = tomllib.loads((ROOT / 'crates/unifi-server/Cargo.toml').read_text())
        self.assertEqual(package['bin'][0]['name'], 'mcp-unifi-rs')
        dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        self.assertRegex(dockerfile, r'(?m)^FROM rust:\$\{RUST_VERSION\}-slim-bookworm@sha256:[0-9a-f]{64} AS builder$')
        self.assertIn('--bin mcp-unifi-rs', dockerfile)
        self.assertIn('ENTRYPOINT ["/mcp-unifi-rs"]', dockerfile)
        self.assertIn('CMD ["/mcp-unifi-rs", "--healthcheck"]', dockerfile)
        self.assertIn('https://github.com/chrisbennight/mcp-unifi-rs', dockerfile)
        for name in ('.dockerignore', '.gitignore'):
            self.assertIn('.worktrees', (ROOT / name).read_text())


if __name__ == '__main__':
    unittest.main()
