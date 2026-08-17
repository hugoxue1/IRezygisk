import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ModulePropStatusContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.monitor = (ROOT / "loader/src/ptracer/monitor.c").read_text(
            encoding="utf-8"
        )
        cls.common = (ROOT / "common.mk").read_text(encoding="utf-8")

    def test_previous_status_prefixes_are_replaced_not_accumulated(self) -> None:
        self.assertIn("skip_previous_status_prefixes", self.monitor)
        self.assertIn("while (description[0] == '[')", self.monitor)
        self.assertIn('strstr(description, "] ")', self.monitor)
        self.assertIn("description = end + 2", self.monitor)

    def test_module_prop_is_read_as_a_complete_dynamic_line(self) -> None:
        self.assertIn("getline(&line, &line_capacity, orig_prop)", self.monitor)
        self.assertIn("free(line);", self.monitor)
        self.assertNotIn("char line[1024]", self.monitor)

    def test_sections_are_reset_and_every_append_is_bounded(self) -> None:
        self.assertIn("pre_section[0] = '\\0';", self.monitor)
        self.assertIn("post_section[0] = '\\0';", self.monitor)
        self.assertIn("append_prop_section", self.monitor)
        prepare = self.monitor.split("static bool prepare_environment()", 1)[1]
        prepare = prepare.split("#define DOMAINLESS_BROKER_FD_ENV", 1)[0]
        self.assertNotIn("strcat(", prepare)
        self.assertIn("module.prop has no description field", prepare)

    def test_i21_version_is_monotonic(self) -> None:
        self.assertIn("VER_NAME ?= v1.0.0-i21", self.common)
        self.assertIn("VER_CODE ?= 558", self.common)


if __name__ == "__main__":
    unittest.main()
