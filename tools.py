"""Read-only starter tools for an authorized, local Pwnable/CTF agent.

Only files inside <project>/workspace can be inspected. The tools never execute
challenge binaries or accept arbitrary shell commands.
"""

from __future__ import annotations

import ast
import operator
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

# Always anchored to this module's directory, not the process working directory.
WORKSPACE = (Path(__file__).resolve().parent / "workspace").resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB per inspected file
MAX_EXPLOIT_SIZE = 100 * 1024     # 100 KiB per generated exploit
MAX_OUTPUT = 8000                 # characters returned to the LLM per tool call
COMMAND_TIMEOUT = 10              # seconds per external command


def _safe_file(path: str) -> Path:
    """Accept workspace-relative paths and absolute paths *inside* workspace."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = WORKSPACE / candidate
    candidate = candidate.resolve()

    try:
        candidate.relative_to(WORKSPACE)
    except ValueError as exc:
        raise ValueError("file path must remain inside workspace/") from exc

    if not candidate.is_file():
        raise FileNotFoundError(f"not a file: {path}")
    if candidate.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(f"file is larger than {MAX_FILE_SIZE // (1024 * 1024)} MiB")
    return candidate


def _run(argv: list[str]) -> str:
    """Run a fixed, read-only command. Never invoke a shell."""
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return f"Error: '{argv[0]}' is not installed (try sudo apt install file binutils)"
    except subprocess.TimeoutExpired:
        return f"Error: command timed out after {COMMAND_TIMEOUT}s"

    output = (p.stdout + ("\n" + p.stderr if p.stderr else "")).strip()
    if p.returncode != 0:
        return f"Error: {argv[0]} returned exit code {p.returncode}: {output[:MAX_OUTPUT]}"
    return output[:MAX_OUTPUT] + ("\n[output truncated]" if len(output) > MAX_OUTPUT else "")


def list_files() -> str:
    """Show file names in the workspace, not arbitrary machine directories."""
    if not WORKSPACE.is_dir():
        return "Error: workspace/ does not exist; create it and copy CTF files there"

    names = []
    for path in sorted(WORKSPACE.rglob("*")):
        if not path.is_file():
            continue
        # Avoid listing symlinks that resolve outside workspace.
        try:
            path.resolve().relative_to(WORKSPACE)
        except ValueError:
            continue
        names.append(str(path.relative_to(WORKSPACE)))
        if len(names) >= 80:
            return "\n".join(names) + "\n[file list limited to 80 entries]"
    return "\n".join(names) if names else "workspace/ is empty"


def file_info(path: str) -> str:
    """Report the file type, size and basic binary metadata."""
    p = _safe_file(path)
    detected = _run(["file", "-b", "--", str(p)])
    return f"File: {p.name}\nSize: {p.stat().st_size} bytes\nType: {detected}"


def read_file(path: str) -> str:
    """Read a *text* source/config file. For binaries use the other tools."""
    p = _safe_file(path)
    raw = p.read_bytes()
    if b"\x00" in raw[:1024]:
        return "Error: binary file; use file_info, elf_headers or extract_strings instead"
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "Error: not valid UTF-8 text; use extract_strings or file_info"
    return content[:MAX_OUTPUT] + ("\n[output truncated]" if len(content) > MAX_OUTPUT else "")


def elf_headers(path: str) -> str:
    """Inspect ELF architecture, type, entry point and program headers."""
    p = _safe_file(path)
    return _run(["readelf", "-W", "-h", "-l", "--", str(p)])


def elf_security(path: str) -> str:
    """Summarize common ELF exploit mitigations from readelf metadata."""
    p = _safe_file(path)
    header = _run(["readelf", "-W", "-h", "--", str(p)])
    program_headers = _run(["readelf", "-W", "-l", "--", str(p)])
    dynamic = _run(["readelf", "-W", "-d", "--", str(p)])
    symbols = _run(["readelf", "-W", "--dyn-syms", "--", str(p)])

    for output in (header, program_headers, dynamic, symbols):
        if output.startswith("Error:"):
            return output
    if "ELF Header:" not in header:
        return "Error: file is not a readable ELF binary"

    type_match = re.search(r"^\s*Type:\s+(\S+)", header, re.MULTILINE)
    elf_type = type_match.group(1) if type_match else "unknown"
    has_interp = re.search(r"^\s*INTERP\s", program_headers, re.MULTILINE) is not None
    if elf_type == "EXEC":
        pie = "No (ET_EXEC)"
    elif elf_type == "DYN" and has_interp:
        pie = "Yes (ET_DYN with PT_INTERP)"
    elif elf_type == "DYN":
        pie = "Not applicable or not detected (ET_DYN without PT_INTERP)"
    else:
        pie = f"Unknown (ELF type {elf_type})"

    stack_match = re.search(
        r"^\s*GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+([A-Z-]+)",
        program_headers,
        re.MULTILINE,
    )
    if stack_match:
        stack_flags = stack_match.group(1)
        nx = "Disabled (executable GNU_STACK)" if "E" in stack_flags else "Enabled"
    else:
        nx = "Unknown (GNU_STACK not present)"

    has_relro = re.search(r"^\s*GNU_RELRO\s", program_headers, re.MULTILINE) is not None
    bind_now = "BIND_NOW" in dynamic or re.search(r"FLAGS_1.*\bNOW\b", dynamic) is not None
    if has_relro and bind_now:
        relro = "Full"
    elif has_relro:
        relro = "Partial"
    else:
        relro = "None"

    canary = "Detected" if re.search(r"__stack_chk_(?:fail|guard)", symbols) else "Not detected"
    return (
        f"ELF security summary: {p.name}\n"
        f"ELF type: {elf_type}\n"
        f"PIE: {pie}\n"
        f"NX: {nx}\n"
        f"RELRO: {relro}\n"
        f"Stack canary: {canary}\n"
        "Note: mitigations are inferred from ELF headers, segments, dynamic tags, and symbols."
    )


def elf_symbols(path: str, keyword: str = "") -> str:
    """List ELF symbols; optionally filter by a case-insensitive substring."""
    p = _safe_file(path)
    raw = _run(["readelf", "-W", "-s", "--", str(p)])
    if raw.startswith("Error:"):
        return raw
    lines = [line for line in raw.splitlines() if not keyword or keyword.lower() in line.lower()]
    if not lines:
        return "No matching symbols (the binary may be stripped)"
    excerpt = "\n".join(lines[:80])
    return excerpt[:MAX_OUTPUT] + ("\n[output truncated]" if len(lines) > 80 or len(excerpt) > MAX_OUTPUT else "")


def extract_strings(path: str, keyword: str = "") -> str:
    """Extract printable strings from a file; optionally filter by substring."""
    p = _safe_file(path)
    if len(keyword) > 100:
        return "Error: keyword is too long (max 100 characters)"
    raw = _run(["strings", "-a", "-n", "4", "--", str(p)])
    if raw.startswith("Error:"):
        return raw
    matches = [line for line in raw.splitlines() if not keyword or keyword.lower() in line.lower()]
    if not matches:
        return "No matching strings in the returned excerpt"
    return "\n".join(matches[:60])[:MAX_OUTPUT] + ("\n[list limited to 60 strings]" if len(matches) > 60 else "")


def disassemble(path: str, symbol: str = "main") -> str:
    """Show x86 Intel-style disassembly for a symbol (default main).

    Use symbol='' to view the first part of the entire disassembly.
    """
    p = _safe_file(path)
    if symbol and not re.fullmatch(r"[A-Za-z0-9_.$@]+", symbol):
        return "Error: invalid symbol name"
    argv = ["objdump", "-d", "-M", "intel"]
    if symbol:
        argv.append(f"--disassemble={symbol}")
    argv.extend(["--", str(p)])
    output = _run(argv)
    if symbol and not output.startswith("Error:") and "<" + symbol + ">:" not in output:
        return f"Symbol '{symbol}' was not found in disassembly (may be stripped). Try symbol='' or elf_symbols.\n{output[:1200]}"
    return output


_BINOPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod, ast.Pow: operator.pow,
    ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
    ast.BitXor: operator.xor, ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}
_UNARYOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Invert: operator.invert}


def calculate(expression: str) -> str:
    """Evaluate basic arithmetic and integer/hex bit operations without eval()."""
    if len(expression) > 120:
        return "Error: expression too long"
    try:
        tree = ast.parse(expression, mode="eval")
        if sum(1 for _ in ast.walk(tree)) > 32:
            return "Error: expression too complex"

        def compute(node):
            if isinstance(node, ast.Constant) and type(node.value) in (int, float):
                result = node.value
            elif isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOPS:
                result = _UNARYOPS[type(node.op)](compute(node.operand))
            elif isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
                left, right = compute(node.left), compute(node.right)
                if isinstance(node.op, (ast.Pow, ast.LShift, ast.RShift)) and (right < 0 or right > 256):
                    raise ValueError("exponent/shift outside 0..256")
                result = _BINOPS[type(node.op)](left, right)
            else:
                raise ValueError("unsupported expression")
            if not isinstance(result, (int, float)) or abs(result) > 2**256:
                raise ValueError("result exceeds allowed range")
            return result

        return str(compute(tree.body))
    except (SyntaxError, ArithmeticError, TypeError, ValueError, OverflowError) as exc:
        return f"Error: {exc}"


def write_exploit(code: str) -> str:
    """Save syntactically valid Python source to workspace/exploit.py without running it."""
    if not isinstance(code, str) or not code.strip():
        return "Error: exploit source must be a non-empty string"
    if len(code.encode("utf-8")) > MAX_EXPLOIT_SIZE:
        return f"Error: exploit source exceeds {MAX_EXPLOIT_SIZE // 1024} KiB"
    try:
        compile(code, "exploit.py", "exec")
    except (SyntaxError, ValueError) as exc:
        line = getattr(exc, "lineno", None)
        return f"Error: exploit source has invalid Python syntax at line {line}: {exc}"

    WORKSPACE.mkdir(parents=True, exist_ok=True)
    target = WORKSPACE / "exploit.py"
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=WORKSPACE,
            prefix=".exploit-",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_file.write(code)
            temp_path = Path(temp_file.name)
        temp_path.replace(target)
    except OSError as exc:
        return f"Error: could not save exploit source: {exc}"
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    return "Saved syntactically valid exploit source to workspace/exploit.py. It was not executed."


def get_current_date() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


TOOL_FUNCTIONS = {
    "list_files": list_files,
    "file_info": file_info,
    "read_file": read_file,
    "elf_headers": elf_headers,
    "elf_security": elf_security,
    "elf_symbols": elf_symbols,
    "extract_strings": extract_strings,
    "disassemble": disassemble,
    "calculate": calculate,
    "write_exploit": write_exploit,
    "get_current_date": get_current_date,
}


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


_PATH = {
    "type": "string",
    "description": "Path to a challenge file, relative to workspace/ or absolute within workspace/. Do not use project paths outside workspace/.",
}

TOOL_SCHEMAS: list[dict] = [
    _schema("list_files", "List available challenge files inside workspace/.", {}, []),
    _schema("file_info", "Identify a challenge file's type, size, architecture hints.", {"path": _PATH}, ["path"]),
    _schema("read_file", "Read a UTF-8 challenge source or text file (not a binary).", {"path": _PATH}, ["path"]),
    _schema("elf_headers", "Read ELF header and program headers using readelf. Use for architecture, PIE type and GNU_STACK/RELRO clues; do not infer full checksec from this alone.", {"path": _PATH}, ["path"]),
    _schema("elf_security", "Summarize common ELF protections: PIE, NX, RELRO, and stack canary. Use on ELF challenge binaries; results are metadata-based indicators.", {"path": _PATH}, ["path"]),
    _schema("elf_symbols", "List functions and symbols from an ELF file, optionally filtered.", {
        "path": _PATH,
        "keyword": {"type": "string", "description": "Optional case-insensitive name substring"},
    }, ["path"]),
    _schema("extract_strings", "Show printable strings in a challenge file, optionally filtered. This is not the complete file content.", {
        "path": _PATH,
        "keyword": {"type": "string", "description": "Optional case-insensitive substring"},
    }, ["path"]),
    _schema("disassemble", "Disassemble an ELF symbol with objdump in Intel syntax; default 'main'. Use empty symbol for the first part of full disassembly.", {
        "path": _PATH,
        "symbol": {"type": "string", "description": "ELF symbol name (default main), or empty string for full excerpt"},
    }, ["path"]),
    _schema("calculate", "Basic arithmetic and integer bitwise operations, including hex addresses. No Python function calls.", {
        "expression": {"type": "string", "description": "Expression, e.g. '2 ** 10' or '0x401000 + 0x30'"},
    }, ["expression"]),
    _schema("write_exploit", "Save valid Python exploit source to workspace/exploit.py (replaces an existing generated file). Syntax is checked; the code is never executed.", {
        "code": {"type": "string", "description": "Complete Python source code for the authorized CTF exploit."},
    }, ["code"]),
    _schema("get_current_date", "Return local date and time.", {}, []),
]


def call_tool(name: str, arguments: dict) -> str:
    """Stable interface expected by core.py; return errors as text to the LLM."""
    fn = TOOL_FUNCTIONS.get(name)
    if fn is None:
        return f"Unknown tool: '{name}'"
    if not isinstance(arguments, dict):
        return "Error: tool arguments must be a JSON object"
    try:
        return str(fn(**arguments))
    except Exception as exc:
        return f"Tool '{name}' raised an error: {exc}"
