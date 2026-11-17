import json
import unittest

from systemd_auditor.cli import main as cli_main

from ._helpers import StagedTree


class EndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = StagedTree()

    def tearDown(self) -> None:
        self.tree.cleanup()

    def test_override_conf_disabling_sandbox_is_visible(self) -> None:
        self.tree.write(
            "etc/systemd/system/app.service",
            "[Service]\n"
            "User=app\n"
            "ExecStart=/usr/bin/appd\n"
            "ProtectSystem=strict\n"
            "ProtectHome=yes\n"
            "PrivateTmp=yes\n"
            "CapabilityBoundingSet=CAP_NET_RAW\n",
        )
        override = self.tree.write(
            "etc/systemd/system/app.service.d/override.conf",
            "[Service]\nProtectSystem=no\nCapabilityBoundingSet=\n",
        )
        report = self.tree.audit("app.service")

        self.assertEqual(report.config.scalar("ProtectSystem"), "off")
        self.assertEqual(report.config.scalar("ProtectHome"), "tmpfs")
        self.assertEqual(report.config.scalar("PrivateTmp"), "yes")
        self.assertEqual(report.config.get("CapabilityBoundingSet").value, ())

        protect = report.config.get("ProtectSystem")
        self.assertEqual(protect.last_origin.path, override)
        self.assertEqual(protect.last_origin.section, "Service")

        text = report.to_text()
        self.assertIn("HARDENING_PROTECT_SYSTEM_OFF", text)
        self.assertIn("override.conf:2", text)
        self.assertIn("CAPABILITY_EMPTY_SET", text)

    def test_dict_report_contains_origins(self) -> None:
        self.tree.write(
            "etc/systemd/system/app.service",
            "[Service]\nUser=app\nProtectSystem=full\n",
        )
        report = self.tree.audit("app.service")
        payload = report.to_dict()
        json.dumps(payload)
        entry = payload["effective"]["ProtectSystem"]
        self.assertEqual(entry["value"], "full")
        self.assertTrue(entry["origin"]["path"].endswith("app.service"))
        self.assertEqual(entry["origin"]["section"], "Service")

    def test_preset_evaluation(self) -> None:
        self.tree.write(
            "etc/systemd/system/app.service", "[Service]\nExecStart=/bin/true\n"
        )
        self.tree.preset("50-default.preset", "disable *\nenable app.service\n")
        report = self.tree.audit("app.service")
        self.assertTrue(report.unit.preset.enabled)
        self.assertEqual(report.unit.preset.matched_rule, "enable app.service")
        self.assertTrue(
            report.unit.preset.origin.path.endswith("50-default.preset")
        )

    def test_wildcard_preset_is_default_and_specific_rule_wins(self) -> None:
        self.tree.write(
            "etc/systemd/system/app.service", "[Service]\nExecStart=/bin/true\n"
        )
        self.tree.preset("50-default.preset", "disable *\nenable app.service\n")
        report = self.tree.audit("app.service")
        self.assertTrue(report.unit.preset.enabled)
        self.assertEqual(report.unit.preset.matched_rule, "enable app.service")

        other = self.tree.audit("other.service")
        self.assertFalse(other.unit.preset.enabled)
        self.assertEqual(other.unit.preset.matched_rule, "disable *")

    def test_missing_unit_emits_warning(self) -> None:
        report = self.tree.audit("ghost.service")
        self.assertTrue(any("no unit file" in item for item in report.warnings))

    def test_masked_unit_warns(self) -> None:
        import os

        target = os.path.join(self.tree.unit_root, "masked.service")
        os.symlink("/dev/null", target)
        report = self.tree.audit("masked.service")
        self.assertTrue(any("masked" in item for item in report.warnings))

    def test_cli_json_output(self) -> None:
        from io import StringIO
        from contextlib import redirect_stdout

        self.tree.write(
            "etc/systemd/system/app.service",
            "[Service]\nExecStart=/bin/true\nProtectSystem=strict\n",
        )
        buffer = StringIO()
        with redirect_stdout(buffer):
            exit_code = cli_main(
                [
                    "app.service",
                    "--root",
                    self.tree.unit_root,
                    "--path-prefix",
                    self.tree.root,
                    "--json",
                ]
            )
        payload = json.loads(buffer.getvalue())
        self.assertIn("effective", payload)
        self.assertEqual(
            payload["effective"]["ProtectSystem"]["value"], "strict"
        )
        self.assertIn(exit_code, (0, 1))


if __name__ == "__main__":
    unittest.main()
