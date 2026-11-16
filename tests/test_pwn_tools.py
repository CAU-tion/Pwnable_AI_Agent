import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import core
import tools
from providers import LLMMessage, ToolCall


class PwnToolTests(unittest.TestCase):
    def test_new_tools_are_available_to_the_agent(self):
        expected = {
            "elf_imports",
            "elf_relocations",
            "cyclic_pattern",
            "find_cyclic_offset",
        }
        self.assertTrue(expected.issubset(tools.TOOL_FUNCTIONS))
        schema_names = {item["function"]["name"] for item in tools.TOOL_SCHEMAS}
        self.assertTrue(expected.issubset(schema_names))

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


if __name__ == "__main__":
    unittest.main()
