from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WorkflowContractTests(unittest.TestCase):
    def test_external_actions_are_pinned_to_immutable_commits(self) -> None:
        workflow = (ROOT / ".gitea" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        action_refs = re.findall(r"^\s*-?\s*uses:\s+([^#\s]+)", workflow, re.MULTILINE)

        self.assertGreaterEqual(len(action_refs), 2)
        for action_ref in action_refs:
            self.assertRegex(action_ref, r"@[0-9a-f]{40}$")

    def test_rust_builder_image_is_pinned_to_an_immutable_digest(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

        self.assertRegex(
            dockerfile,
            r"(?m)^FROM rust:\$\{RUST_VERSION\}-slim-bookworm@sha256:[0-9a-f]{64} AS builder$",
        )

    def test_image_smoke_passes_configuration_by_environment_name(self) -> None:
        workflow = (ROOT / ".gitea" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("_FILE", workflow)
        self.assertNotIn("docker cp", workflow)
        for command in ["docker create", "docker start"]:
            self.assertIn(command, workflow)
        for variable in [
            "UNIFI_MCP_LOG_LEVEL",
            "UNIFI_MCP_GATEWAY_BEARER_CURRENT",
            "UNIFI_MCP_IDENTITY_JWKS_URL",
            "UNIFI_MCP_IDENTITY_ISSUER",
            "UNIFI_MCP_IDENTITY_ACTOR",
            "UNIFI_MCP_CONTROLLER_URL",
            "UNIFI_MCP_CONTROLLER_API_KEY",
            "UNIFI_MCP_CONTROLLER_USERNAME",
            "UNIFI_MCP_CONTROLLER_PASSWORD",
        ]:
            self.assertIn(f"-e {variable} \\", workflow)

    def test_manifest_emission_is_gated_in_ci(self) -> None:
        workflow = (ROOT / ".gitea" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("--emit-gateway-manifest", workflow)
        for line in (
            "name: unifi",
            "classification_mode: mcp_annotations",
            "bearer_env: MCP_GATEWAY_UPSTREAM_BEARER_UNIFI",
            "isolation: per_call",
        ):
            self.assertIn(line, workflow)

    def test_registry_credentials_come_only_from_infisical(self) -> None:
        workflow = (ROOT / ".gitea" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("infisical-secrets-action", workflow)
        self.assertIn("secret-path: /bennight/unifi-mcp-rs", workflow)
        self.assertNotIn("secrets.REGISTRY_TOKEN", workflow)
        self.assertNotIn("secrets.REGISTRY_USER", workflow)


if __name__ == "__main__":
    unittest.main()
