import os
import stat
import unittest

from ._helpers import StagedTree


class TemplateInstanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = StagedTree()

    def tearDown(self) -> None:
        self.tree.cleanup()

    def test_template_main_file_and_instance_dropins(self) -> None:
        self.tree.write(
            "etc/systemd/system/worker@.service",
            "[Service]\nUser=svc\nExecStart=/usr/bin/worker --slot %i\n",
        )
        self.tree.write(
            "etc/systemd/system/worker@.service.d/10-common.conf",
            "[Service]\nProtectSystem=full\n",
        )
        self.tree.write(
            "etc/systemd/system/worker@edge.service.d/20-edge.conf",
            "[Service]\nPrivateTmp=yes\n",
        )
        report = self.tree.audit("worker@edge.service")
        self.assertEqual(report.unit.template_name, "worker@.service")
        self.assertEqual(report.unit.instance, "edge")
        self.assertTrue(report.unit.main_file.path.endswith("worker@.service"))
        dropin_names = [os.path.basename(item.path) for item in report.unit.dropins]
        self.assertEqual(dropin_names, ["10-common.conf", "20-edge.conf"])

        command = report.exec_commands[0]
        self.assertEqual(command.argv, ("/usr/bin/worker", "--slot", "edge"))
        self.assertEqual(command.executable, "/usr/bin/worker")

    def test_specifier_in_readwrite_paths(self) -> None:
        self.tree.write(
            "etc/systemd/system/worker@.service",
            "[Service]\nReadWritePaths=/var/lib/%i\n",
        )
        self.tree.write("var/lib/edge/.keep", "")
        report = self.tree.audit("worker@edge.service")
        self.assertEqual(
            list(report.config.get("ReadWritePaths").value), ["/var/lib/edge"]
        )


class EnvironmentFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = StagedTree()

    def tearDown(self) -> None:
        self.tree.cleanup()

    def test_environment_file_feeds_exec_expansion(self) -> None:
        self.tree.write("etc/app/worker.env", 'MODE=fast\nPATH=/opt/bin:/usr/bin\n')
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\n"
            "EnvironmentFile=/etc/app/worker.env\n"
            "ExecStart=worker --mode $MODE\n",
        )
        self.tree.executable("opt/bin/worker")
        report = self.tree.audit("worker.service")
        command = report.exec_commands[0]
        self.assertEqual(command.argv, ("worker", "--mode", "fast"))
        self.assertTrue(command.executable.endswith("/opt/bin/worker"))
        self.assertEqual(report.environment["MODE"], "fast")

    def test_optional_missing_environment_file_warns_softly(self) -> None:
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nEnvironmentFile=-/etc/app/missing.env\nExecStart=/bin/true\n",
        )
        report = self.tree.audit("worker.service")
        self.assertEqual(report.environment_files, ())
        self.assertNotIn(
            "missing",
            " ".join(report.warnings),
        )

    def test_required_missing_environment_file_warns(self) -> None:
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nEnvironmentFile=/etc/app/missing.env\nExecStart=/bin/true\n",
        )
        report = self.tree.audit("worker.service")
        self.assertTrue(any("missing" in item for item in report.warnings))


class RelativeExecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = StagedTree()

    def tearDown(self) -> None:
        self.tree.cleanup()

    def test_relative_program_resolved_via_path(self) -> None:
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nEnvironment=PATH=/opt/bin\nExecStart=worker --serve\n",
        )
        self.tree.executable("opt/bin/worker")
        report = self.tree.audit("worker.service")
        command = report.exec_commands[0]
        self.assertEqual(command.argv[0], "worker")
        self.assertTrue(command.executable.endswith("/opt/bin/worker"))

    def test_exec_prefixes_and_relative_with_slash(self) -> None:
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nExecStart=-!./scripts/run.sh\n",
        )
        report = self.tree.audit("worker.service")
        command = report.exec_commands[0]
        self.assertTrue(command.ignore_failure)
        self.assertIn("!", command.prefixes)
        self.assertEqual(command.executable, "./scripts/run.sh")


class PathPermissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = StagedTree()

    def tearDown(self) -> None:
        self.tree.cleanup()

    def test_world_writable_binary_is_flagged(self) -> None:
        binary = self.tree.executable("opt/bin/worker")
        os.chmod(binary, 0o777)
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nExecStart=/opt/bin/worker\n",
        )
        report = self.tree.audit("worker.service")
        finding = next(item for item in report.findings if item.code == "EXEC_PATH_WRITABLE")
        self.assertEqual(finding.principal, "other")
        self.assertEqual(finding.target_path, "/opt/bin/worker")
        self.assertEqual(stat.filemode(finding.mode), "-rwxrwxrwx")

    def test_group_writable_directory_flags_replacement_vector(self) -> None:
        self.tree.executable("srv/app/run")
        self.tree.chmod("srv/app", 0o775)
        self.tree.non_root_owner("srv/app")
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nExecStart=/srv/app/run\n",
        )
        report = self.tree.audit("worker.service")
        codes = {item.code for item in report.findings}
        self.assertIn("EXEC_PATH_WRITABLE", codes)

    def test_sticky_world_writable_directory_is_not_replacement_vector(self) -> None:
        self.tree.executable("tmp-staging/run")
        self.tree.chmod("tmp-staging", 0o1777)
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nExecStart=/tmp-staging/run\n",
        )
        report = self.tree.audit("worker.service")
        self.assertNotIn(
            "EXEC_PATH_WRITABLE",
            {item.code for item in report.findings},
        )

    def test_root_owned_readonly_binary_produces_no_finding(self) -> None:
        self.tree.executable("usr/bin/secure")
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nExecStart=/usr/bin/secure\n",
        )
        report = self.tree.audit("worker.service")
        self.assertNotIn(
            "EXEC_PATH_WRITABLE",
            {item.code for item in report.findings},
        )

    def test_missing_executable_is_reported(self) -> None:
        self.tree.write(
            "etc/systemd/system/worker.service",
            "[Service]\nExecStart=/usr/bin/gone\n",
        )
        report = self.tree.audit("worker.service")
        self.assertIn(
            "EXEC_PATH_MISSING",
            {item.code for item in report.findings},
        )


if __name__ == "__main__":
    unittest.main()
