#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from providers import create_provider
from reliability import run_agent_reliable
from tools import WORKSPACE


DEFAULT_MODEL = "gemini-3.6-flash"


PWNABLE_SYSTEM_PROMPT = """
You are an AI agent for solving authorized pwnable and CTF challenges.

Your goal is to analyze the challenge systematically and use available
tools when evidence is needed.

Rules:
- Work only on authorized CTF or pwnable challenge environments.
- Use tools to inspect evidence when necessary.
- Do not invent command outputs, file contents, addresses, offsets,
  protections, vulnerabilities, or tool results.
- Base conclusions on evidence obtained from the challenge and tools.
- Build exploit code from observed symbols, offsets, gadgets, and protections; do not invent addresses or payload layouts.
- Save a complete Python exploit with write_exploit, then use run_exploit on the supplied local challenge when available.
- When a challenge binary uses relative files, launch it with the binary's parent directory as its process cwd.
- Treat exit status, stdout, and stderr as evidence. If it crashes or fails, use debug_binary or other tools, revise the code, and retry.
- Report success only when the exploit output actually shows the challenge result or flag.
- After each tool result, reassess the current hypothesis before
  choosing the next action.
- Keep track of useful findings such as protections, vulnerabilities,
  addresses, offsets, and failed attempts.
- When enough evidence is available, explain the final result clearly.

Typical workflow:
1. Identify the provided challenge files.
2. Inspect file type and architecture; use elf_security for ELF protections.
3. Analyze program behavior and relevant code paths. Use elf_imports and
   elf_relocations for imported functions and GOT/PLT entries, search_rop_gadgets
   for candidate gadgets, and dump_elf_section or search_elf_bytes for data
   sections and embedded strings.
4. Verify candidate vulnerabilities. For a buffer overwrite, use cyclic_pattern
   and find_cyclic_offset. Use debug_binary to inspect a relevant breakpoint,
   registers, and instructions when static output is not enough.
5. Write a complete exploit based on observed evidence. Prefer pwntools ELF/ROP
   helpers for addresses and packing, match send() versus sendline() to the
   target's input behavior, and set process(elf.path, cwd=os.path.dirname(elf.path))
   when the challenge expects files relative to its binary.
6. Save the code with write_exploit. If a local challenge binary is available,
   run it with run_exploit, inspect its output and exit status, then revise and
   retry after failures. Continue until the challenge succeeds or evidence shows
   what is still missing.
7. Record failed attempts and avoid repeating them.

When challenge files are provided, inspect the actual files using tools.
Never assume their contents from their filenames alone.
""".strip()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnable-agent",
        description="Gemini-based AI agent for authorized pwnable/CTF challenges.",
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Gemini model to use (default: {DEFAULT_MODEL})",
    )

    parser.add_argument(
        "--file",
        "-f",
        action="append",
        default=[],
        help="Challenge file path. Can be specified multiple times.",
    )

    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Run in interactive mode.",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Hide tool execution trace.",
    )

    parser.add_argument(
        "--output",
        "-o",
        help="Write the task, tool trace, and final answer to a .md or .txt report.",
    )

    parser.add_argument(
        "task",
        nargs="*",
        help="Pwnable/CTF challenge description or task.",
    )

    return parser


def resolve_files(paths: list[str]) -> list[Path]:
    """
    Validate the given file or directory paths.
    If a directory is provided, recursively collect all files inside it.
    """
    resolved_files: list[Path] = []

    for input_path in paths:
        path = Path(input_path).expanduser().resolve()

        if not path.exists():
            raise FileNotFoundError(
                f"Path does not exist: {input_path}"
            )

        # Single file
        if path.is_file():
            resolved_files.append(path)
            continue

        # Directory
        if path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    resolved_files.append(child.resolve())

            continue

        raise ValueError(
            f"Unsupported path: {input_path}"
        )

    # Remove duplicate paths while preserving order
    resolved_files = list(dict.fromkeys(resolved_files))

    return resolved_files


@contextmanager
def stage_challenge_files(files: list[Path]) -> Iterator[list[Path]]:
    """Copy challenge files into the safe workspace and preserve sibling paths.

    The temporary directory lives under WORKSPACE so every staged file passes
    tools._safe_file(), and is removed when the agent run finishes. Files with
    a shared parent keep their relative layout so binaries can find adjacent
    data files and libraries during local execution.
    """
    if not files:
        yield []
        return

    WORKSPACE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".run-", dir=WORKSPACE) as temp_dir:
        staging_root = Path(temp_dir)
        staged_files: list[Path] = []
        sources = [Path(source_path).resolve(strict=True) for source_path in files]
        try:
            common_parent = Path(os.path.commonpath([str(source.parent) for source in sources]))
        except ValueError:
            # Different drives/filesystems cannot share a relative tree.
            common_parent = None

        for index, source in enumerate(sources, start=1):
            if not source.is_file():
                raise ValueError(f"Challenge input is not a file: {source}")

            relative_path = (
                source.relative_to(common_parent)
                if common_parent is not None
                else Path(f"{index:03d}") / source.name
            )
            target = staging_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            staged_files.append(target)

        yield staged_files


def build_task(task: str, files: list[Path]) -> str:
    """
    사용자 요청과 challenge 파일 정보를 하나의 Agent task로 합친다.
    """
    parts = []

    if task:
        parts.append(task)

    if files:
        parts.append("\nProvided challenge files:")

        for path in files:
            try:
                relative_path = path.resolve().relative_to(WORKSPACE).as_posix()
            except ValueError as exc:
                raise ValueError(
                    "Challenge files must be staged inside workspace/ before building the task"
                ) from exc
            parts.append(f"- {relative_path}")

        parts.append(
            "\nThese paths are relative to workspace/. Inspect the files "
            "using the available tools before "
            "drawing conclusions."
        )

    return "\n".join(parts)


def write_analysis_report(
    report_path: str | Path,
    task: str,
    answer: str,
    events: list[dict],
) -> Path:
    """Write the final answer and observed tool trace to Markdown or text."""
    path = Path(report_path).expanduser()
    suffix = path.suffix.lower()
    if suffix not in {".md", ".txt"}:
        raise ValueError("Report path must end with .md or .txt")

    tool_calls = [event for event in events if event.get("event") == "tool_call"]
    if suffix == ".md":
        lines = [
            "# Pwnable Analysis Report",
            "",
            "## Task",
            "",
            task,
            "",
            "## Analysis process",
            "",
        ]
        if tool_calls:
            for event in tool_calls:
                args = json.dumps(event.get("args", {}), ensure_ascii=False, sort_keys=True)
                lines.extend(
                    [
                        f"### Step {event.get('step', '?')}: `{event.get('tool', 'unknown')}`",
                        "",
                        f"Arguments: `{args}`",
                        "",
                        "Result:",
                    ]
                )
                result = str(event.get("result", ""))
                quoted_result = [f"> {line}" if line else ">" for line in result.splitlines()]
                lines.extend(quoted_result or [">"])
                lines.append("")
        else:
            lines.extend(["No tools were called.", ""])
        lines.extend(["## Final answer", "", answer, ""])
    else:
        lines = [
            "PWNABLE ANALYSIS REPORT",
            "=" * 24,
            "",
            "TASK",
            "----",
            task,
            "",
            "ANALYSIS PROCESS",
            "-----------------",
        ]
        if tool_calls:
            for event in tool_calls:
                args = json.dumps(event.get("args", {}), ensure_ascii=False, sort_keys=True)
                lines.extend([
                    f"Step {event.get('step', '?')}: {event.get('tool', 'unknown')}",
                    f"Arguments: {args}",
                    "Result:",
                    str(event.get("result", "")),
                    "",
                ])
        else:
            lines.extend(["No tools were called.", ""])
        lines.extend(["FINAL ANSWER", "------------", answer, ""])

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def run_task(
    task: str,
    model: str,
    files: list[Path] | None = None,
    verbose: bool = True,
    report_path: str | Path | None = None,
) -> str:

    if files is None:
        files = []

    if report_path is not None:
        report = Path(report_path).expanduser()
        if report.suffix.lower() not in {".md", ".txt"}:
            raise ValueError("Report path must end with .md or .txt")
        if report.exists() and report.is_dir():
            raise ValueError("Report path points to a directory")
        if report.resolve() in {Path(file).resolve() for file in files}:
            raise ValueError("Report path cannot overwrite a provided challenge file")

    with stage_challenge_files(files) as staged_files:
        full_task = build_task(
            task=task,
            files=staged_files,
        )

        provider = create_provider(
            "gemini",
            model,
        )

        events: list[dict] = []
        answer = run_agent_reliable(
            task=full_task,
            provider=provider,
            system_prompt=PWNABLE_SYSTEM_PROMPT,
            verbose=verbose,
            event_callback=events.append if report_path is not None else None,
        )
        if report_path is not None:
            write_analysis_report(report_path, full_task, answer, events)
        return answer


def run_interactive(
    model: str,
    files: list[Path] | None = None,
    verbose: bool = True,
) -> None:

    if files is None:
        files = []

    print("Pwnable Agent interactive mode")

    if files:
        print("\nChallenge files:")

        for path in files:
            print(f"  - {path}")

    print("\nType 'exit' to quit.\n")

    while True:
        try:
            task = input("Challenge> ").strip()

        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            break

        if task.lower() in {"exit", "quit", "q"}:
            print("Goodbye.")
            break

        if not task:
            continue

        try:
            answer = run_task(
                task=task,
                model=model,
                files=files,
                verbose=verbose,
            )

            print(f"\nAgent: {answer}\n")

        except Exception as e:
            print(f"\nError: {e}\n")


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    verbose = not args.quiet

    try:
        challenge_files = resolve_files(args.file)

    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    print("=" * 46)
    print("          Pwnable AI Agent")
    print("=" * 46)
    print("Provider : Gemini")
    print(f"Model    : {args.model}")

    if challenge_files:
        print("Files    :")

        for path in challenge_files:
            print(f"           {path}")

    print()

    if args.interactive:
        if args.output:
            parser.error("--output cannot be combined with --interactive")
        run_interactive(
            model=args.model,
            files=challenge_files,
            verbose=verbose,
        )
        return

    task = " ".join(args.task).strip()

    if not task and not challenge_files:
        parser.print_help()
        sys.exit(0)

    # 파일만 넣고 task를 생략해도 동작
    if not task:
        task = (
            "Analyze the provided pwnable challenge files and "
            "identify the vulnerability."
        )

    print(f"Task: {task}\n")

    try:
        answer = run_task(
            task=task,
            model=args.model,
            files=challenge_files,
            verbose=verbose,
            report_path=args.output,
        )

        print(f"\nAnswer: {answer}\n")
        if args.output:
            print(f"Report written to: {Path(args.output).expanduser().resolve()}")

    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)

    except Exception as e:
        print(f"\nError: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
