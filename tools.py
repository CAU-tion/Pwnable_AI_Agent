"""Local analysis and exploit-validation tools for authorized Pwnable/CTF work.

Challenge files are restricted to <project>/workspace. External analysis tools
use fixed argument lists; run_exploit executes only workspace/exploit.py.
"""

from __future__ import annotations

import ast
import os
import operator
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# Always anchored to this module's directory, not the process working directory.
WORKSPACE = (Path(__file__).resolve().parent / "workspace").resolve()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB per inspected file
MAX_EXPLOIT_SIZE = 100 * 1024     # 100 KiB per generated exploit
MAX_OUTPUT = 8000                 # characters returned to the LLM per tool call
COMMAND_TIMEOUT = 10              # seconds per external command
MAX_CYCLIC_LENGTH = 4096          # keep generated patterns within model context
MAX_DEBUG_INPUT = 64 * 1024       # bytes passed to a local GDB run
_CYCLIC_ALPHABET = "abcdefghijklmnopqrstuvwxyz"


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


def elf_imports(path: str, keyword: str = "") -> str:
    """List undefined dynamic symbols, which often reveal useful libc calls."""
    p = _safe_file(path)
    raw = _run(["readelf", "-W", "--dyn-syms", "--", str(p)])
    if raw.startswith("Error:"):
        return raw
    imports = [
        line.strip()
        for line in raw.splitlines()
        if re.search(r"\bUND\b", line)
        and (not keyword or keyword.lower() in line.lower())
    ]
    if not imports:
        return "No matching undefined dynamic symbols were found"
    excerpt = "\n".join(imports[:80])
    return excerpt[:MAX_OUTPUT] + (
        "\n[imports truncated]" if len(imports) > 80 or len(excerpt) > MAX_OUTPUT else ""
    )


def elf_relocations(path: str, keyword: str = "") -> str:
    """List ELF relocations, including GOT/PLT entries used in common exploits."""
    p = _safe_file(path)
    raw = _run(["readelf", "-W", "-r", "--", str(p)])
    if raw.startswith("Error:"):
        return raw
    lines = [
        line.rstrip()
        for line in raw.splitlines()
        if not keyword or keyword.lower() in line.lower()
    ]
    if not lines:
        return "No matching relocations were found"
    excerpt = "\n".join(lines[:100])
    return excerpt[:MAX_OUTPUT] + (
        "\n[relocations truncated]" if len(lines) > 100 or len(excerpt) > MAX_OUTPUT else ""
    )


def search_rop_gadgets(path: str, keyword: str = "", limit: int = 40) -> str:
    """Search a challenge ELF for ROP gadgets, optionally filtering the output."""
    if not isinstance(keyword, str) or len(keyword) > 100:
        return "Error: keyword must be a string of at most 100 characters"
    if type(limit) is not int or not 1 <= limit <= 100:
        return "Error: limit must be between 1 and 100"

    p = _safe_file(path)
    executable = shutil.which("ROPgadget")
    if executable is None:
        venv_executable = Path(sys.prefix) / (
            "Scripts/ROPgadget.exe" if os.name == "nt" else "bin/ROPgadget"
        )
        if venv_executable.is_file():
            executable = str(venv_executable)
    if executable is None:
        return "Error: ROPgadget is not installed; install project requirements in the Linux/WSL environment"

    argv = [executable, "--binary", str(p)]
    first_instruction = re.match(r"\s*([a-z][a-z0-9]*)\b", keyword.lower())
    if first_instruction and first_instruction.group(1) in {
        "add", "and", "call", "inc", "lea", "mov", "neg", "not", "or",
        "pop", "push", "ret", "sub", "syscall", "xchg", "xor",
    }:
        mnemonic = first_instruction.group(1)
        allowed = mnemonic if mnemonic == "ret" else f"{mnemonic}|ret"
        argv.extend(["--only", allowed])

    raw = _run(argv)
    if raw.startswith("Error:"):
        return raw
    gadgets = [
        line.strip()
        for line in raw.splitlines()
        if re.match(r"\s*0x[0-9a-fA-F]+\s*:", line)
        and (not keyword or keyword.casefold() in line.casefold())
    ]
    if not gadgets:
        return "No matching ROP gadgets were found"
    excerpt = "\n".join(gadgets[:limit])
    return excerpt + (f"\n[showing {limit} of {len(gadgets)} matching gadgets]" if len(gadgets) > limit else "")


def dump_elf_section(path: str, section: str) -> str:
    """Show bytes and addresses for a named ELF section such as .data or .init_array."""
    if not isinstance(section, str) or len(section) > 80 or not re.fullmatch(r"[A-Za-z0-9_.$-]+", section):
        return "Error: invalid ELF section name"
    p = _safe_file(path)
    return _run(["objdump", "-s", "-j", section, "--", str(p)])


def search_elf_bytes(path: str, pattern: str, limit: int = 20) -> str:
    """Find text or hex bytes in a file and map ELF loadable bytes to virtual addresses."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
        return "Error: pattern must contain 1 to 512 characters"
    if type(limit) is not int or not 1 <= limit <= 100:
        return "Error: limit must be between 1 and 100"

    if pattern[:4].casefold() == "hex:":
        try:
            needle = bytes.fromhex(pattern[4:])
        except ValueError as exc:
            return f"Error: invalid hex pattern: {exc}"
    else:
        needle = pattern.encode("utf-8")
    if not needle or len(needle) > 256:
        return "Error: search pattern must contain 1 to 256 bytes"

    p = _safe_file(path)
    data = p.read_bytes()
    offsets: list[int] = []
    cursor = 0
    while len(offsets) < limit + 1:
        cursor = data.find(needle, cursor)
        if cursor < 0:
            break
        offsets.append(cursor)
        cursor += 1
    if not offsets:
        return "No matching bytes were found"

    load_segments: list[tuple[int, int, int]] = []
    if data.startswith(b"\x7fELF"):
        headers = _run(["readelf", "-W", "-l", "--", str(p)])
        if not headers.startswith("Error:"):
            for line in headers.splitlines():
                fields = line.split()
                if fields and fields[0] == "LOAD" and len(fields) >= 6:
                    try:
                        load_segments.append((
                            int(fields[1], 0),
                            int(fields[2], 0),
                            int(fields[4], 0),
                        ))
                    except ValueError:
                        continue

    results = []
    for offset in offsets[:limit]:
        addresses = [
            virtual_address + offset - file_offset
            for file_offset, virtual_address, file_size in load_segments
            if file_offset <= offset < file_offset + file_size
        ]
        address_text = ", ".join(f"ELF VA 0x{address:x}" for address in addresses)
        row = f"file offset 0x{offset:x}"
        if address_text:
            row += f" -> {address_text}"
        results.append(row)

    suffix = f"\n[showing {limit} of at least {len(offsets)} matches]" if len(offsets) > limit else ""
    if load_segments:
        suffix += "\nELF virtual addresses are relative to the image; PIE needs its runtime base."
    return "\n".join(results) + suffix


def debug_binary(path: str, breakpoint: str, input_hex: str = "",
                 registers: str = "rip,rsp,rax,rdi,rsi,rdx", instructions: int = 6) -> str:
    """Run a bounded GDB inspection at one breakpoint with selected registers."""
    breakpoint_pattern = r"(?:0[xX][0-9a-fA-F]+|[A-Za-z_.$][A-Za-z0-9_.$@]*(?:\+0[xX]?[0-9a-fA-F]+)?)"
    if not isinstance(breakpoint, str) or not re.fullmatch(breakpoint_pattern, breakpoint):
        return "Error: breakpoint must be a symbol, symbol+offset, or hex address"
    if not isinstance(input_hex, str) or len(input_hex) > MAX_DEBUG_INPUT * 2 + 256:
        return f"Error: debug input exceeds {MAX_DEBUG_INPUT} bytes"
    if type(instructions) is not int or not 1 <= instructions <= 16:
        return "Error: instructions must be between 1 and 16"

    register_names = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
    }
    if not isinstance(registers, str):
        return "Error: registers must be a comma-separated list"
    requested_registers = list(dict.fromkeys(part.strip().lower() for part in registers.split(",") if part.strip()))
    if not requested_registers or len(requested_registers) > 12 or any(name not in register_names for name in requested_registers):
        return "Error: select up to 12 supported x86/x86-64 registers"

    try:
        input_bytes = bytes.fromhex(input_hex) if input_hex.strip() else b""
    except ValueError as exc:
        return f"Error: invalid hex input: {exc}"
    if len(input_bytes) > MAX_DEBUG_INPUT:
        return f"Error: debug input exceeds {MAX_DEBUG_INPUT} bytes"

    p = _safe_file(path)
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        argv = ["gdb", "-q", "-batch", "-nx", "-ex", "set pagination off", "-ex", "set confirm off"]
        argv.extend(["-ex", f"break *({breakpoint})"])
        if input_bytes:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=WORKSPACE, prefix=".gdb-input-", delete=False
            ) as input_file:
                input_file.write(input_bytes)
                temp_path = Path(input_file.name)
            argv.extend(["-ex", f"run < {shlex.quote(str(temp_path))}"])
        else:
            argv.extend(["-ex", "run"])
        argv.extend([
            "-ex", f"x/{instructions}i $pc",
            "-ex", f"info registers {' '.join(requested_registers)}",
            "-ex", "bt 5",
            str(p),
        ])
        result = subprocess.run(
            argv,
            cwd=WORKSPACE,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return "Error: GDB is not installed in the agent's Linux/WSL environment"
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return f"Error: GDB timed out after {COMMAND_TIMEOUT}s\n{partial[:MAX_OUTPUT]}"
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    output = (result.stdout + ("\n" + result.stderr if result.stderr else "")).strip()
    if result.returncode != 0:
        return f"Error: GDB returned exit code {result.returncode}\n{output[:MAX_OUTPUT]}"
    return output[:MAX_OUTPUT] + ("\n[output truncated]" if len(output) > MAX_OUTPUT else "")


def _de_bruijn_prefix(alphabet: str, width: int, length: int) -> str:
    """Generate a prefix whose width-sized windows are unique."""
    base = len(alphabet)
    working = [0] * (base * width)
    result: list[str] = []

    def visit(position: int, period: int) -> None:
        if len(result) >= length:
            return
        if position > width:
            if width % period == 0:
                for index in working[1 : period + 1]:
                    result.append(alphabet[index])
                    if len(result) >= length:
                        return
            return

        working[position] = working[position - period]
        visit(position + 1, period)
        for index in range(working[position - period] + 1, base):
            if len(result) >= length:
                return
            working[position] = index
            visit(position + 1, position)

    visit(1, 1)
    return "".join(result)


def cyclic_pattern(length: int, width: int = 4) -> str:
    """Generate a bounded de Bruijn pattern for finding overwrite offsets."""
    if type(length) is not int or not 1 <= length <= MAX_CYCLIC_LENGTH:
        return f"Error: length must be between 1 and {MAX_CYCLIC_LENGTH}"
    if type(width) is not int or width not in {4, 8}:
        return "Error: width must be 4 or 8 bytes"
    return _de_bruijn_prefix(_CYCLIC_ALPHABET, width, length)


def find_cyclic_offset(value: str, length: int = MAX_CYCLIC_LENGTH,
                       width: int = 4, endian: str = "little") -> str:
    """Find a crash value in a generated pattern (hex register values supported)."""
    if type(length) is not int or not 1 <= length <= MAX_CYCLIC_LENGTH:
        return f"Error: length must be between 1 and {MAX_CYCLIC_LENGTH}"
    if type(width) is not int or width not in {4, 8}:
        return "Error: width must be 4 or 8 bytes"
    if endian not in {"little", "big"}:
        return "Error: endian must be 'little' or 'big'"
    if not isinstance(value, str) or not value:
        return "Error: value must be a hex register value or a byte string"

    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
            needle = int(value, 16).to_bytes(width, endian, signed=False)
        else:
            needle = value.encode("latin-1")
            if len(needle) != width:
                return f"Error: byte-string value must be exactly {width} bytes"
    except (OverflowError, ValueError) as exc:
        return f"Error: {exc}"

    pattern = _de_bruijn_prefix(_CYCLIC_ALPHABET, width, length + width - 1)
    offset = pattern.encode("ascii").find(needle)
    if offset < 0 or offset >= length:
        return f"No offset found in the first {length} bytes of the pattern"
    return f"Offset: {offset} (width={width}, endian={endian})"


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

    return "Saved syntax-checked exploit source to workspace/exploit.py. Call run_exploit to test it against the provided authorized CTF challenge."


def run_exploit(arguments: list[str] | None = None, timeout: int = 15) -> str:
    """Run workspace/exploit.py with a time limit and return output/status for repair."""
    if type(timeout) is not int or not 1 <= timeout <= 60:
        return "Error: timeout must be between 1 and 60 seconds"
    if arguments is None:
        arguments = []
    if (
        not isinstance(arguments, list)
        or len(arguments) > 16
        or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 500 for arg in arguments)
    ):
        return "Error: arguments must be a list of at most 16 strings (500 characters each)"

    try:
        exploit_path = _safe_file("exploit.py")
    except (FileNotFoundError, ValueError) as exc:
        return f"Error: {exc}"
    if exploit_path.stat().st_size > MAX_EXPLOIT_SIZE:
        return f"Error: exploit source exceeds {MAX_EXPLOIT_SIZE // 1024} KiB"

    try:
        process = subprocess.Popen(
            [sys.executable, str(exploit_path), *arguments],
            cwd=WORKSPACE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=(os.name == "posix"),
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            stdout, stderr = process.communicate()
            return (
                f"Timed out after {timeout}s; exploit process was stopped.\n"
                f"STDOUT:\n{stdout[-MAX_OUTPUT:]}\nSTDERR:\n{stderr[-MAX_OUTPUT:]}"
            )
    except OSError as exc:
        return f"Error: could not run exploit with {sys.executable}: {exc}"

    status = f"Exit code: {process.returncode}"
    if process.returncode is not None and process.returncode < 0:
        try:
            status += f" (terminated by {signal.Signals(-process.returncode).name})"
        except ValueError:
            pass
    output = [status]
    if stdout:
        output.append(f"STDOUT:\n{stdout[-MAX_OUTPUT:]}")
    if stderr:
        output.append(f"STDERR:\n{stderr[-MAX_OUTPUT:]}")
    if process.returncode:
        output.append("Exploit did not exit successfully; use the output to revise the script.")
    return "\n".join(output)


def get_current_date() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


TOOL_FUNCTIONS = {
    "list_files": list_files,
    "file_info": file_info,
    "read_file": read_file,
    "elf_headers": elf_headers,
    "elf_security": elf_security,
    "elf_symbols": elf_symbols,
    "elf_imports": elf_imports,
    "elf_relocations": elf_relocations,
    "search_rop_gadgets": search_rop_gadgets,
    "dump_elf_section": dump_elf_section,
    "search_elf_bytes": search_elf_bytes,
    "debug_binary": debug_binary,
    "cyclic_pattern": cyclic_pattern,
    "find_cyclic_offset": find_cyclic_offset,
    "extract_strings": extract_strings,
    "disassemble": disassemble,
    "calculate": calculate,
    "write_exploit": write_exploit,
    "run_exploit": run_exploit,
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
    _schema("elf_imports", "List undefined dynamic symbols imported by an ELF binary. Use to identify useful libc functions such as puts, read, write, system, or gets.", {
        "path": _PATH,
        "keyword": {"type": "string", "description": "Optional case-insensitive substring to filter imported symbol names"},
    }, ["path"]),
    _schema("elf_relocations", "List ELF relocations, including GOT/PLT entries. Use to find addresses for imported functions when planning a leak or GOT overwrite.", {
        "path": _PATH,
        "keyword": {"type": "string", "description": "Optional case-insensitive substring to filter relocation lines, such as a function name"},
    }, ["path"]),
    _schema("search_rop_gadgets", "Search a challenge ELF for ROP gadgets. Use filters such as 'pop rdi', 'pop rsi', 'mov rdx', 'xchg rsp', or 'call rax' when building a chain.", {
        "path": _PATH,
        "keyword": {"type": "string", "description": "Optional case-insensitive text to find in gadget instructions"},
        "limit": {"type": "integer", "description": "Maximum matching gadgets to return (1-100, default 40)"},
    }, ["path"]),
    _schema("dump_elf_section", "Dump bytes and addresses from an ELF section. Useful for .data, .rodata, .bss, and .init_array analysis.", {
        "path": _PATH,
        "section": {"type": "string", "description": "Section name, for example .data or .init_array"},
    }, ["path", "section"]),
    _schema("search_elf_bytes", "Search embedded text or bytes in a challenge binary and report file offsets plus ELF virtual addresses when possible. Prefix a pattern with 'hex:' for raw bytes.", {
        "path": _PATH,
        "pattern": {"type": "string", "description": "UTF-8 text such as 'flag.txt' or hex bytes such as 'hex:666c61672e74787400'"},
        "limit": {"type": "integer", "description": "Maximum matches to return (1-100, default 20)"},
    }, ["path", "pattern"]),
    _schema("debug_binary", "Run a challenge binary under GDB at one validated breakpoint and return selected registers, nearby instructions, and a short backtrace.", {
        "path": _PATH,
        "breakpoint": {"type": "string", "description": "Symbol, symbol+offset (for example pwnme+0x98), or hex address"},
        "input_hex": {"type": "string", "description": "Optional stdin bytes as hex; whitespace is allowed"},
        "registers": {"type": "string", "description": "Comma-separated x86/x86-64 registers, for example rip,rsp,rax (default rip,rsp,rax,rdi,rsi,rdx)"},
        "instructions": {"type": "integer", "description": "Number of nearby instructions to show, from 1 to 16 (default 6)"},
    }, ["path", "breakpoint"]),
    _schema("cyclic_pattern", "Generate a bounded de Bruijn pattern for measuring a buffer overwrite offset. Use width 4 for 32-bit values or width 8 for 64-bit values.", {
        "length": {"type": "integer", "description": "Pattern length from 1 to 4096 bytes"},
        "width": {"type": "integer", "description": "Crash value width: 4 or 8 bytes (default 4)"},
    }, ["length"]),
    _schema("find_cyclic_offset", "Find where a crashed register value occurs in the cyclic pattern. For a hex register value such as 0x6161616c, endian defaults to little.", {
        "value": {"type": "string", "description": "Hex register value (for example 0x6161616c) or exactly width bytes copied from the crash"},
        "length": {"type": "integer", "description": "Length of the original pattern, from 1 to 4096 bytes (default 4096)"},
        "width": {"type": "integer", "description": "Register value width: 4 or 8 bytes (default 4)"},
        "endian": {"type": "string", "description": "Byte order used to display the register value: little (default) or big"},
    }, ["value"]),
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
    _schema("write_exploit", "Save a complete Python exploit source to workspace/exploit.py (replaces an existing generated file). Python syntax is checked; call run_exploit to execute and test it against the authorized challenge.", {
        "code": {"type": "string", "description": "Complete Python source code for the authorized CTF exploit."},
    }, ["code"]),
    _schema("run_exploit", "Run workspace/exploit.py with a maximum 60-second limit. Returns exit status and stdout/stderr so you can diagnose crashes and revise the exploit. Use only for the provided authorized CTF challenge.", {
        "arguments": {"type": "array", "items": {"type": "string"}, "description": "Optional command-line arguments for the exploit script"},
        "timeout": {"type": "integer", "description": "Maximum runtime in seconds, from 1 to 60 (default 15)"},
    }, []),
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
