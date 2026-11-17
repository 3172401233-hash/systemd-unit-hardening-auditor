import unittest

from systemd_auditor.capabilities import CapabilityAccumulator

from ._helpers import StagedTree


class CapabilityMergeTests(unittest.TestCase):
    def test_or_merge_then_inverted_and(self) -> None:
        acc = CapabilityAccumulator()
        acc.apply("CAP_NET_RAW CAP_NET_BIND_SERVICE")
        result = acc.apply("~CAP_SYS_ADMIN")
        self.assertIn("CAP_NET_RAW", result)
        self.assertIn("CAP_NET_BIND_SERVICE", result)
        self.assertNotIn("CAP_SYS_ADMIN", result)

    def test_empty_assignment_resets_to_empty_set(self) -> None:
        acc = CapabilityAccumulator()
        acc.apply("CAP_NET_RAW")
        self.assertEqual(acc.apply(""), frozenset())

    def test_bare_tilde_restores_full_set(self) -> None:
        acc = CapabilityAccumulator()
        acc.apply("CAP_NET_RAW")
        acc.apply("")
        self.assertEqual(len(acc.apply("~")), 41)

    def test_bare_names_are_canonicalized(self) -> None:
        acc = CapabilityAccumulator()
        result = acc.apply("net_raw 10")
        self.assertEqual(result, {"CAP_NET_RAW", "CAP_NET_BIND_SERVICE"})


class DropInMergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = StagedTree()

    def tearDown(self) -> None:
        self.tree.cleanup()

    def test_dropin_overrides_scalar_and_appends_lists(self) -> None:
        self.tree.unit(
            "web.service",
            "[Service]\nUser=old\nProtectSystem=full\nReadWritePaths=/srv/a\n",
        )
        self.tree.dropin(
            "web.service",
            "10-override.conf",
            "[Service]\nUser=new\nReadWritePaths=/srv/b\n",
        )
        report = self.tree.audit("web.service")
        self.assertEqual(report.config.scalar("User"), "new")
        origin = report.config.get("User").last_origin
        self.assertTrue(origin.path.endswith("10-override.conf"))
        self.assertEqual(
            list(report.config.get("ReadWritePaths").value), ["/srv/a", "/srv/b"]
        )

    def test_empty_assignment_resets_scalar_to_blank(self) -> None:
        self.tree.unit("web.service", "[Service]\nUser=svc\nGroup=g\n")
        self.tree.dropin("web.service", "99.conf", "[Service]\nUser=\n")
        report = self.tree.audit("web.service")
        user = report.config.get("User")
        self.assertEqual(user.value, "")
        self.assertTrue(user.last_origin.path.endswith("99.conf"))
        self.assertEqual(report.config.scalar("Group"), "g")

    def test_empty_assignment_resets_list_before_rebuild(self) -> None:
        self.tree.unit(
            "web.service",
            "[Service]\nReadWritePaths=/keep-away /also-away\nExecStart=/old\n",
        )
        self.tree.dropin(
            "web.service",
            "99.conf",
            "[Service]\nReadWritePaths=\nReadWritePaths=/srv/new\nExecStart=\nExecStart=/new\n",
        )
        report = self.tree.audit("web.service")
        self.assertEqual(
            list(report.config.get("ReadWritePaths").value), ["/srv/new"]
        )
        self.assertEqual(
            list(report.config.get("ExecStart").value), ["/new"]
        )

    def test_protect_system_disabled_in_dropin_is_flagged_with_origin(self) -> None:
        self.tree.unit("web.service", "[Service]\nProtectSystem=strict\n")
        override = self.tree.dropin(
            "web.service", "override.conf", "[Service]\nProtectSystem=no\n"
        )
        report = self.tree.audit("web.service")
        self.assertEqual(report.config.scalar("ProtectSystem"), "off")
        finding = next(
            item for item in report.findings if item.code == "HARDENING_PROTECT_SYSTEM_OFF"
        )
        self.assertEqual(finding.origin.path, override)
        self.assertEqual(finding.origin.section, "Service")
        self.assertEqual(finding.origin.line, 2)

    def test_capability_changes_through_dropins(self) -> None:
        self.tree.unit(
            "web.service",
            "[Service]\nCapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE\n",
        )
        self.tree.dropin(
            "web.service", "10.conf", "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN\n"
        )
        report = self.tree.audit("web.service")
        caps = set(report.config.get("CapabilityBoundingSet").value)
        self.assertEqual(
            caps,
            {"CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"},
        )

        self.tree.dropin("web.service", "20.conf", "[Service]\nCapabilityBoundingSet=\n")
        report = self.tree.audit("web.service")
        self.assertEqual(report.config.get("CapabilityBoundingSet").value, ())
        codes = {item.code for item in report.findings}
        self.assertIn("CAPABILITY_EMPTY_SET", codes)

    def test_empty_reset_keeps_reset_origin(self) -> None:
        self.tree.unit(
            "web.service",
            "[Service]\nExecStart=/old\nReadWritePaths=/a\n",
        )
        self.tree.dropin(
            "web.service", "z.conf", "[Service]\nExecStart=\nReadWritePaths=\n"
        )
        report = self.tree.audit("web.service")
        exec_value = report.config.get("ExecStart")
        self.assertEqual(exec_value.value, ())
        self.assertTrue(exec_value.last_origin.path.endswith("z.conf"))
        rwp = report.config.get("ReadWritePaths")
        self.assertEqual(rwp.value, ())
        self.assertEqual(rwp.last_origin.raw_value, "")


if __name__ == "__main__":
    unittest.main()
