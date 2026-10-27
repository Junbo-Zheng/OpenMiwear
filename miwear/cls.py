#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
#
# Copyright (C) 2026 Junbo Zheng. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Clean a device log dir over the NSH serial console, keeping only one file.

The host side does all the work (recursive ls + per-file rm), because NSH has
no glob, no for-loop, and rm takes a single path per call.
"""

import argparse
import re
import sys
import time

import serial

try:
    from miwear import __version__
except ImportError:
    __version__ = "0.0.1"

BAUDRATE = 921600

PROMPT_RE = re.compile(r"^\s*(ap|sensor|cp|audio|tee|nsh)>\s*$")
LOG_RE = re.compile(r"^\d\d/\d\d \d\d:\d\d:")


class NshSession:
    """Minimal NSH console session over USB CDC serial."""

    def __init__(self, port: str, baudrate: int = BAUDRATE, keep: str = "tmp.log"):
        self.ser = serial.Serial(port, baudrate, timeout=0.2)
        self.keep = keep
        self.wake()

    def wake(self):
        """USB CDC console sleeps; poke it until a command round-trips."""
        for _ in range(8):
            self.ser.reset_input_buffer()
            self.ser.write(b"\r\n")
            self._drain(0.8)
            out = self.run("echo CLS_PING", wait=1.5)
            if "CLS_PING" in out and "command not found" not in out:
                return
        raise RuntimeError("console not responding to echo probe")

    def _drain(self, seconds: float, until_prompt: bool = False) -> str:
        buf = b""
        end = time.time() + seconds
        while time.time() < end:
            data = self.ser.read(32000)
            if data:
                buf += data
                if until_prompt:
                    # strip ANSI escapes first: the prompt line is "ap> \x1b[K"
                    plain = re.sub(
                        r"\x1b\[[0-9;?]*[A-Za-z]", "", buf.decode(errors="replace")
                    )
                    lines = plain.splitlines()
                    if lines and PROMPT_RE.match(lines[-1]):
                        break
        return buf.decode(errors="replace")

    def run(self, cmd: str, wait: float = 1.5) -> str:
        self.ser.write(cmd.encode() + b"\r\n")
        # wait is only the timeout ceiling; the prompt ends the read early
        return self._drain(wait, until_prompt=True)

    @staticmethod
    def clean_lines(raw: str, cmd: str) -> list:
        """Drop device log noise, prompts, ANSI escapes and the command echo."""
        lines = []
        for ln in raw.replace("\x00", "").splitlines():
            ln = re.sub(r"\x1b\[K", "", ln).strip()
            if not ln or LOG_RE.match(ln) or PROMPT_RE.match(ln):
                continue
            if ln.rstrip("\r") == cmd:
                continue
            lines.append(ln)
        return lines

    def ls_entries(self, path: str) -> tuple:
        """Return ([(name, size)], [dirname]) for regular files and subdirs."""
        raw = self.run(f"ls -l {path}", wait=2.5)
        files, dirs = [], []
        for ln in self.clean_lines(raw, f"ls -l {path}"):
            parts = ln.split()
            if len(parts) < 4:
                continue
            if ln.startswith("-"):
                files.append((parts[-1], int(parts[-2])))
            elif ln.startswith("d") and parts[-1] not in (".", ".."):
                dirs.append(parts[-1].rstrip("/"))
        if not files and not dirs:
            for ln in self.clean_lines(raw, f"ls -l {path}"):
                if "nsh:" in ln:
                    raise RuntimeError(ln)
        return files, dirs

    def walk(self, root: str) -> tuple:
        """Recursively collect (keep_files, delete_files) as full paths."""
        keep: list = []
        doomed: list = []
        stack = [root.rstrip("/") or "/"]
        while stack:
            d = stack.pop()
            files, dirs = self.ls_entries(d)
            for name, size in files:
                (keep if name == self.keep else doomed).append((f"{d}/{name}", size))
            stack += [f"{d}/{sub}" for sub in dirs]
        return keep, doomed

    def rm(self, path: str):
        """Delete one file; return the nsh error line on failure, else None."""
        for ln in self.clean_lines(self.run(f"rm {path}"), f"rm {path}"):
            if "nsh:" in ln:
                return ln
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Clean a device log dir over the NSH serial console, "
        "keeping only the keep-file (default tmp.log), recursively",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Notes:
  - log path differs per project: eMMC products use /log,
    NAND products use /data/log; the two never coexist.
  - Only regular files are deleted; directories are left in place.

Examples:
  %(prog)s                                     # clean /data/log, keep tmp.log
  %(prog)s /log                                # clean /log (eMMC projects)
  %(prog)s -n                                  # dry-run: list only
  %(prog)s -p /dev/ttyACM0 -k keep.txt /log    # other port / keep-file
  %(prog)s --version                           # show version information
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version information and exit",
    )

    parser.add_argument(
        "dir",
        nargs="?",
        default="/data/log",
        help="Log dir on device (default: /data/log)",
    )

    parser.add_argument(
        "-p",
        "--port",
        type=str,
        default="/dev/ttyACM1",
        help="Specify serial device path (default: /dev/ttyACM1)",
    )

    parser.add_argument(
        "-k",
        "--keep",
        type=str,
        default="tmp.log",
        help="File name to keep at every level (default: tmp.log)",
    )

    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="List what would be deleted, delete nothing",
    )

    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip the y/N confirmation",
    )

    args = parser.parse_args()

    try:
        nsh = NshSession(args.port, keep=args.keep)
        keep, doomed = nsh.walk(args.dir)
    except serial.SerialException as e:
        print(f"error: cannot open {args.port}: {e}")
        return 2
    except RuntimeError as e:
        print(f"error: {e}")
        return 2

    total = sum(size for _, size in doomed if size > 0)
    print(f"{args.dir}: {len(keep) + len(doomed)} file(s), keeping {args.keep}")
    for name, size in keep:
        print(f"  keep   {name} ({size}B)")
    for name, size in doomed:
        print(f"  delete {name} ({size}B)")

    if not doomed:
        print("nothing to delete")
        return 0

    if args.dry_run:
        print(f"dry-run: would delete {len(doomed)} file(s), ~{total}B")
        return 0

    if not args.yes:
        ans = input(f"delete {len(doomed)} file(s)? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted")
            return 1

    failed = []
    for name, _ in doomed:
        err = nsh.rm(name)
        if err:
            failed.append(name)
            print(f"  FAIL {name}: {err}")
        else:
            print(f"  deleted {name}")

    _, remaining = nsh.walk(args.dir)
    remaining = [n for n, _ in remaining]
    if not remaining:
        print(f"done: only {args.keep} remains (all levels)")
    else:
        print(f"remaining: {remaining}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
