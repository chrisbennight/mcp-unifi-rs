import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tags = load("image_tags")
smoke = load("smoke_image")


class ImageTagsTests(unittest.TestCase):
    def test_main_updates_latest_and_full_source_tag(self):
        self.assertEqual(tags.image_tags("a" * 40, "refs/heads/main"), ["sha-" + "a" * 40, "latest"])

    def test_version_push_never_updates_latest(self):
        for version in ("v1.2.3", "v1.2.3-rc.1"):
            self.assertEqual(tags.image_tags("b" * 40, "refs/tags/" + version), ["sha-" + "b" * 40, version])

    def test_rejects_untrusted_or_unpublishable_inputs(self):
        for sha in ("a" * 12, "A" * 40, "$(id)", "a" * 40 + "\n"):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                tags.image_tags(sha, "refs/heads/main")
        for ref in ("refs/pull/1/merge", "refs/heads/feature", "refs/tags/latest", "refs/tags/v1.2.3\nlatest", "refs/tags/v1.2.3-$(id)", "refs/tags/v1.2.3-" + "x" * 128):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                tags.image_tags("a" * 40, ref)

    def test_invalid_cli_input_emits_no_tags(self):
        result = subprocess.run(
            ["python3", str(SCRIPTS / "image_tags.py"), "--sha", "a" * 40, "--ref", "refs/pull/1/merge"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


class ImageSmokeTests(unittest.TestCase):
    def test_each_surface_uses_fake_credentials_and_no_network(self):
        for surface, prefix in (("network", "CONTROLLER"), ("protect", "PROTECT")):
            with self.subTest(surface=surface), patch.object(smoke.subprocess, "run") as run:
                run.return_value.returncode = 0
                smoke.smoke("example/image:source", surface)
                create = run.call_args_list[0]
                argv = create.args[0]
                self.assertIn("--pull=never", argv)
                self.assertEqual(argv[-1], "example/image:source")
                self.assertEqual(argv[argv.index("--network") + 1], "none")
                self.assertIn("--read-only", argv)
                self.assertEqual(create.kwargs["env"]["UNIFI_MCP_SURFACE"], surface)
                key = "UNIFI_MCP_" + prefix + "_API_KEY"
                self.assertIn(key, argv)
                self.assertTrue(create.kwargs["env"][key].startswith("smoke-"))
                self.assertFalse(any("smoke-controller-password" in arg for arg in argv))
                self.assertIn("/mcp-unifi-rs", run.call_args_list[2].args[0])
                self.assertEqual(run.call_args_list[-1].args[0][:3], ["docker", "rm", "-f"])

    def test_liveness_failure_is_reported_and_container_removed(self):
        with patch.object(smoke.subprocess, "run") as run, patch.object(smoke.time, "sleep"):
            run.return_value.returncode = 1
            with self.assertRaisesRegex(RuntimeError, "network container failed"):
                smoke.smoke("example/image:source", "network")
            probes = [call for call in run.call_args_list if call.args[0][1] == "exec"]
            self.assertEqual(len(probes), 30)
            self.assertEqual(run.call_args_list[-1].args[0][:3], ["docker", "rm", "-f"])

    def test_start_failure_still_removes_container(self):
        with patch.object(smoke.subprocess, "run") as run:
            run.side_effect = [None, subprocess.CalledProcessError(1, ["docker", "start"]), None]
            with self.assertRaises(subprocess.CalledProcessError):
                smoke.smoke("example/image:source", "protect")
            self.assertEqual(run.call_args_list[-1].args[0][:3], ["docker", "rm", "-f"])


if __name__ == "__main__":
    unittest.main()
