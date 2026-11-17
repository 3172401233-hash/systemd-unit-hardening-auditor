import os
import unittest

from systemd_auditor.parser import parse_env_file, parse_unit_file

from ._helpers import StagedTree


class ParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = StagedTree()

    def tearDown(self) -> None:
        self.tree.cleanup()

    def test_comments_blank_lines_and_sections(self) -> None:
        path = self.tree.unit(
            "x.service",
            """\
# leading comment
; another comment

[Unit]
Description=hello
[Service]
User=daemon
""",
        )
        parsed = parse_unit_file(path)
        self.assertEqual(parsed.parse_errors, ())
        keys = {(line.section, line.key, line.value) for line in parsed.lines}
        self.assertIn(("Unit", "Description", "hello"), keys)
        self.assertIn(("Service", "User", "daemon"), keys)

    def test_line_continuation_is_concatenated(self) -> None:
        path = self.tree.unit(
            "x.service",
            "[Service]\nExecStart=/bin/app \\\n  --flag \\\n  --other\n",
        )
        parsed = parse_unit_file(path)
        directive = parsed.directives("Service", "ExecStart")[0]
        self.assertEqual(directive.value, "/bin/app   --flag   --other")
        self.assertEqual(directive.line, 2)

    def test_directive_without_equals_is_reported(self) -> None:
        path = self.tree.unit("x.service", "[Service]\nBrokenLine\nUser=ok\n")
        parsed = parse_unit_file(path)
        self.assertEqual(len(parsed.parse_errors), 1)
        self.assertIn("missing '='", parsed.parse_errors[0])
        self.assertEqual(parsed.directives("Service", "User")[0].value, "ok")

    def test_env_file_quoting_and_export(self) -> None:
        path = self.tree.write(
            "etc/app.env",
            '# c\nexport GREETING="hello world"\nPLAIN=plain\nNUM=42\n',
        )
        values, warnings = parse_env_file(path)
        self.assertEqual(warnings, ())
        self.assertEqual(
            values, {"GREETING": "hello world", "PLAIN": "plain", "NUM": "42"}
        )

    def test_drop_in_ordering_lexicographic_then_directory(self) -> None:
        from systemd_auditor.parser import collect_unit_files

        run_root = os.path.join(self.tree.root, "run/systemd/system")
        os.makedirs(run_root, exist_ok=True)
        self.tree.dropin("x.service", "50-run-only.conf", "[Service]\nUser=run\n")
        os.makedirs(os.path.join(run_root, "x.service.d"), exist_ok=True)
        with open(os.path.join(run_root, "x.service.d", "10-run.conf"), "w") as handle:
            handle.write("[Service]\nGroup=run\n")

        _, _, _, dropins, _ = collect_unit_files(
            [self.tree.unit_root, run_root], "x.service", None
        )
        names = [os.path.basename(path) for path in dropins]
        self.assertEqual(names, ["10-run.conf", "50-run-only.conf"])

    def test_same_named_dropin_prefers_etc_over_run(self) -> None:
        from systemd_auditor.parser import collect_unit_files

        run_root = os.path.join(self.tree.root, "run/systemd/system")
        os.makedirs(os.path.join(run_root, "x.service.d"), exist_ok=True)
        with open(os.path.join(run_root, "x.service.d", "10-x.conf"), "w") as handle:
            handle.write("[Service]\nUser=run\n")
        self.tree.dropin("x.service", "10-x.conf", "[Service]\nUser=etc\n")

        _, _, _, dropins, _ = collect_unit_files(
            [self.tree.unit_root, run_root], "x.service", None
        )
        self.assertEqual(len(dropins), 1)
        self.assertIn(self.tree.unit_root, dropins[0])


if __name__ == "__main__":
    unittest.main()
