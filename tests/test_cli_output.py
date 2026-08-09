#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import cli  # noqa: E402


class CliOutputTests(unittest.TestCase):
    def render(self, result: dict, **kwargs) -> str:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            cli.print_result(result, **kwargs)
        return stream.getvalue()

    def test_disassembly_is_one_instruction_per_line(self):
        result = {
            "status": "ok",
            "result": {
                "address": "0x107777",
                "name": "ac_game_play_effect",
                "instruction_count": 2,
                "instructions": [
                    {"address": "0x107777", "disasm": "push    10h"},
                    {"address": "0x10777c", "disasm": "call    __CHK"},
                ],
            },
        }
        self.assertEqual(
            self.render(result),
            "0x107777  push    10h\n0x10777c  call    __CHK\n",
        )

    def test_flat_record_lists_repeat_column_names_only_once(self):
        result = {
            "result": {
                "count": 2,
                "functions": [
                    {"address": "0x401000", "name": "main"},
                    {"address": "0x401020", "name": "helper"},
                ],
            }
        }
        self.assertEqual(
            self.render(result),
            "count: 2\nfunctions:\n  address\tname\n  0x401000\tmain\n  0x401020\thelper\n",
        )

    def test_multiline_text_is_not_json_escaped(self):
        result = {"result": {"name": "main", "pseudocode": "int main()\n{\n  return 0;\n}"}}
        self.assertEqual(
            self.render(result),
            "name: main\npseudocode:\n  int main()\n  {\n    return 0;\n  }\n",
        )

    def test_json_output_preserves_structured_result(self):
        data = {"address": "0x401000", "instructions": []}
        rendered = self.render({"result": data}, output="json")
        self.assertEqual(json.loads(rendered), data)

    def test_non_disassembly_instruction_list_uses_generic_text(self):
        result = {"result": {"processor": "metapc", "count": 2, "instructions": ["aaa", "aad"]}}
        self.assertEqual(
            self.render(result),
            "processor: metapc\ncount: 2\ninstructions: aaa, aad\n",
        )

    def test_raw_output_preserves_full_envelope(self):
        envelope = {"status": "ok", "result": {"value": 7}}
        rendered = self.render(envelope, raw=True)
        self.assertEqual(json.loads(rendered), envelope)


if __name__ == "__main__":
    unittest.main()
