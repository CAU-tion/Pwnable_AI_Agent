import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import core
import agent
import reliability
import tools
from providers import LLMMessage, ToolCall


class PwnToolTests(unittest.TestCase):
    def test_staging_keeps_sibling_challenge_files_together(self):
        with tempfile.TemporaryDirectory() as directory:
            challenge_dir = Path(directory) / "challenge"
            challenge_dir.mkdir()
            binary = challenge_dir / "ret2win"
            flag_file = challenge_dir / "flag.txt"
            binary.write_bytes(b"ELF fixture")
            flag_file.write_text("ROPE{test_flag}\n", encoding="utf-8")

            with agent.stage_challenge_files([binary, flag_file]) as staged:
                staged_binary, staged_flag = staged
                self.assertEqual(staged_binary.parent, staged_flag.parent)
                self.assertEqual(staged_binary.read_bytes(), b"ELF fixture")
                self.assertEqual(staged_flag.read_text(encoding="utf-8"), "ROPE{test_flag}\n")

    def test_new_tools_are_available_to_the_agent(self):
        expected = {
            "elf_imports",
            "elf_relocations",
            "cyclic_pattern",
            "find_cyclic_offset",
            "search_rop_gadgets",
            "dump_elf_section",
            "search_elf_bytes",
            "debug_binary",
            "run_exploit",
        }
        self.assertTrue(expected.issubset(tools.TOOL_FUNCTIONS))
        schema_names = {item["function"]["name"] for item in tools.TOOL_SCHEMAS}
        self.assertTrue(expected.issubset(schema_names))
        for name in expected:
            self.assertIn(name, agent.PWNABLE_SYSTEM_PROMPT)

    def test_agent_executes_a_cyclic_tool_call_and_returns_its_result_to_provider(self):
        class OneToolProvider:
            name = "test-provider"

            def __init__(self):
                self.calls = 0
                self.tool_result = None

            def complete(self, messages, offered_tools):
                self.calls += 1
                offered_names = {item["function"]["name"] for item in offered_tools}
                self.assert_cyclic_available(offered_names)
                if self.calls == 1:
                    return LLMMessage(
                        role="assistant",
                        content=None,
                        tool_calls=[
                            ToolCall(
                                id="call-cyclic",
                                name="cyclic_pattern",
                                arguments={"length": 64, "width": 4},
                            )
                        ],
                    )

                self.tool_result = messages[-1]["content"]
                return LLMMessage(role="assistant", content="Offset analysis can continue.")

            @staticmethod
            def assert_cyclic_available(names):
                if "cyclic_pattern" not in names:
                    raise AssertionError("cyclic_pattern was not offered to the provider")

        provider = OneToolProvider()
        with tempfile.TemporaryDirectory() as log_dir:
            with patch.object(core, "_LOG_DIR", Path(log_dir)):
                answer = core.run_agent(
                    task="Generate an overwrite pattern",
                    provider=provider,
                    tools=tools.TOOL_SCHEMAS,
                    verbose=False,
                    max_steps=2,
                    run_id="cyclic-roundtrip",
                )

        self.assertEqual(answer, "Offset analysis can continue.")
        self.assertEqual(provider.calls, 2)
        self.assertEqual(provider.tool_result, tools.cyclic_pattern(64, width=4))

    def test_cyclic_pattern_round_trips_four_byte_little_endian_register(self):
        pattern = tools.cyclic_pattern(256, width=4)
        offset = 112
        register_value = int.from_bytes(pattern[offset : offset + 4].encode(), "little")

        self.assertEqual(
            tools.find_cyclic_offset(hex(register_value), length=256, width=4),
            "Offset: 112 (width=4, endian=little)",
        )

    def test_cyclic_pattern_round_trips_eight_byte_big_endian_register(self):
        pattern = tools.cyclic_pattern(512, width=8)
        offset = 271
        register_value = int.from_bytes(pattern[offset : offset + 8].encode(), "big")

        self.assertEqual(
            tools.find_cyclic_offset(
                hex(register_value), length=512, width=8, endian="big"
            ),
            "Offset: 271 (width=8, endian=big)",
        )

    def test_cyclic_tools_reject_non_integer_sizes_and_widths(self):
        self.assertTrue(tools.cyclic_pattern(True).startswith("Error:"))
        self.assertTrue(tools.cyclic_pattern(32, width=4.0).startswith("Error:"))
        self.assertTrue(
            tools.find_cyclic_offset("0x61616161", width=4.0).startswith("Error:")
        )

    def test_imports_and_relocations_can_be_filtered_for_exploit_targets(self):
        dyn_symbols = (
            "Symbol table '.dynsym' contains 3 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)\n"
            "     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.2.5 (2)\n"
        )
        relocations = (
            "Relocation section '.rela.plt' at offset 0x600 contains 2 entries:\n"
            "  Offset          Info           Type           Sym. Value    Sym. Name + Addend\n"
            "000000404000  000100000007 R_X86_64_JUMP_SLOT 0000000000000000 puts@GLIBC_2.2.5 + 0\n"
            "000000404008  000200000007 R_X86_64_JUMP_SLOT 0000000000000000 read@GLIBC_2.2.5 + 0\n"
        )

        with patch.object(tools, "_safe_file", return_value=tools.WORKSPACE / "fixture"):
            with patch.object(tools, "_run", return_value=dyn_symbols):
                imports = tools.elf_imports("fixture", keyword="puts")
            with patch.object(tools, "_run", return_value=relocations):
                got_entry = tools.elf_relocations("fixture", keyword="puts")

        self.assertIn("puts@GLIBC", imports)
        self.assertNotIn("read@GLIBC", imports)
        self.assertIn("000000404000", got_entry)
        self.assertIn("puts@GLIBC", got_entry)
        self.assertNotIn("read@GLIBC", got_entry)

    def test_rop_gadget_search_returns_matching_gadgets(self):
        gadget_output = (
            "Gadgets information\n"
            "0x00000000004006a3 : pop rdi ; ret\n"
            "0x00000000004006a1 : pop rsi ; pop r15 ; ret\n"
            "Unique gadgets found: 2\n"
        )
        with patch.object(tools, "_safe_file", return_value=tools.WORKSPACE / "fixture"):
            with patch.object(tools.shutil, "which", return_value="/usr/bin/ROPgadget"):
                with patch.object(tools, "_run", return_value=gadget_output):
                    result = tools.search_rop_gadgets("fixture", keyword="pop rdi")

        self.assertIn("0x00000000004006a3 : pop rdi ; ret", result)
        self.assertNotIn("pop rsi", result)

    def test_section_dump_and_byte_search_return_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_bytes(b"\x7fELF" + (b"\x00" * 12) + b"flag.txt\x00" + b"\x00" * 16)
            with patch.object(tools, "_safe_file", return_value=binary):
                with patch.object(tools, "_run", return_value="Contents of section .data:"):
                    section = tools.dump_elf_section("fixture", ".data")
                with patch.object(
                    tools,
                    "_run",
                    return_value=(
                        "Program Headers:\n"
                        "  LOAD 0x0000000000000000 0x0000000000400000 0x0000000000400000 0x0000000000000100 0x0000000000000100 R E 0x1000\n"
                    ),
                ):
                    found = tools.search_elf_bytes("fixture", "flag.txt")

        self.assertIn("Contents of section .data", section)
        self.assertIn("file offset 0x10", found)
        self.assertIn("ELF VA 0x400010", found)

    def test_debug_tool_builds_a_bounded_gdb_request(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            binary.write_bytes(b"fixture")
            with patch.object(tools, "_safe_file", return_value=binary):
                with patch.object(
                    tools.subprocess,
                    "run",
                    return_value=SimpleNamespace(stdout="Breakpoint 1, rax=0x41", stderr="", returncode=0),
                ) as run:
                    result = tools.debug_binary(
                        "fixture",
                        breakpoint="pwnme+0x98",
                        input_hex="41424344",
                        registers="rip,rax",
                        instructions=4,
                    )

        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "gdb")
        self.assertIn("break *(pwnme+0x98)", argv)
        self.assertIn("info registers rip rax", argv)
        self.assertIn("Breakpoint 1", result)

    def test_debug_tool_rejects_gdb_command_injection(self):
        result = tools.debug_binary("fixture", breakpoint="pwnme; shell id")
        self.assertTrue(result.startswith("Error:"))

    def test_run_exploit_returns_exit_status_and_captured_output(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "exploit.py").write_text(
                "import sys\nprint('exploit stdout')\nprint('exploit stderr', file=sys.stderr)\n",
                encoding="utf-8",
            )
            with patch.object(tools, "WORKSPACE", workspace):
                result = tools.run_exploit()

        self.assertIn("Exit code: 0", result)
        self.assertIn("exploit stdout", result)
        self.assertIn("exploit stderr", result)

    def test_run_exploit_reports_timeouts_to_the_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "exploit.py").write_text(
                "import time\ntime.sleep(3)\n", encoding="utf-8"
            )
            with patch.object(tools, "WORKSPACE", workspace):
                result = tools.run_exploit(timeout=1)

        self.assertIn("Timed out after 1s", result)

    def test_reliable_dispatcher_accepts_run_exploit_string_arguments(self):
        with patch.object(reliability, "call_tool", return_value="ran") as dispatch:
            result = reliability.validated_call(
                "run_exploit", {"arguments": ["--local"], "timeout": 3}
            )

        self.assertEqual(result, "ran")
        dispatch.assert_called_once_with(
            "run_exploit", {"arguments": ["--local"], "timeout": 3}
        )


if __name__ == "__main__":
    unittest.main()
