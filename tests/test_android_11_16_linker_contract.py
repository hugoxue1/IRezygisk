import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def function_body(source: str, name: str) -> str:
    start = source.index(name)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated function: {name}")


class Android11To16LinkerContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.utils = (ROOT / "loader/src/ptracer/utils.c").read_text(encoding="utf-8")
        cls.ptracer = (ROOT / "loader/src/ptracer/ptracer.c").read_text(
            encoding="utf-8"
        )

    def test_linker_rendezvous_is_elf_entry_not_syscall_polling(self) -> None:
        body = function_body(self.utils, "bool wait_linker_ready(")
        self.assertIn("wait_for_app_process_entry", body)
        self.assertIn("elf_entry", body)
        self.assertNotIn("PTRACE_SYSCALL", body)
        self.assertNotIn("syscall_steps", body)
        self.assertNotIn("3500L", body)
        for caller in (
            "bool trace_zygote_direct(",
            "bool trace_zygote_postexec(",
            "bool trace_zygote_preexec(",
        ):
            caller_body = function_body(self.ptracer, caller)
            self.assertNotIn("PTRACE_SYSCALL", caller_body)

    def test_all_supported_abis_have_an_entry_trap(self) -> None:
        body = function_body(self.utils, "static bool arm_entry_breakpoint(")
        for architecture in ("__aarch64__", "__arm__", "__x86_64__", "__i386__"):
            self.assertIn(architecture, body)
        self.assertIn("0xd4200000U", body)  # AArch64 BRK
        self.assertIn("0xbe00U", body)  # Thumb BKPT
        self.assertIn("0xe1200070U", body)  # ARM BKPT
        self.assertIn("0xcc", body)  # x86 INT3

    def test_bti_and_cet_landing_pads_are_not_overwritten(self) -> None:
        body = function_body(self.utils, "static bool arm_entry_breakpoint(")
        self.assertIn("runtime_entry + sizeof(instruction)", body)
        self.assertIn("ENDBR64/ENDBR32", body)

    def test_entry_breakpoint_is_restored_on_success_and_timeout(self) -> None:
        body = function_body(self.utils, "static bool wait_for_app_process_entry(")
        self.assertGreaterEqual(body.count("disarm_entry_breakpoint"), 2)
        self.assertIn("PTRACE_INTERRUPT", body)
        self.assertIn("regs.REG_IP = breakpoint.address", body)

    def test_post_exec_fd_close_requires_stable_object_identity(self) -> None:
        close_body = function_body(self.ptracer, "static void remote_close_fd_current(")
        self.assertIn("remote_fd_identity_matches", close_body)
        self.assertIn("descriptor identity changed", close_body)
        self.assertLess(
            close_body.index("remote_fd_identity_matches"),
            close_body.index("remote_close_fd(pid"),
        )

    def test_injector_failure_keeps_fd_for_central_verified_cleanup(self) -> None:
        inject_body = function_body(self.ptracer, "bool inject_on_main(")
        self.assertNotRegex(
            inject_body,
            re.compile(r"remote_close_fd\([^;]*inherited_domainless_fd", re.DOTALL),
        )
        self.assertIn("capture_remote_fd_identity", self.ptracer)
        self.assertIn("domainless descriptor was replaced by the linker", self.ptracer)

    def test_api_30_through_36_share_the_same_version_neutral_contract(self) -> None:
        # Android 11..16 are API 30..36. The rendezvous must not branch on an
        # Android release, SDK property, OEM, module name, or fixed PID.
        body = function_body(self.utils, "bool wait_linker_ready(")
        for forbidden in (
            "ro.build.version.sdk",
            "ANDROID_API",
            "MIUI",
            "zygisk-assistant",
            "zygisk_ckbsmart",
        ):
            self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
