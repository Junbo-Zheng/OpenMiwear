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

import glob
import zipfile
import argparse
import os
from collections import defaultdict
from typing import Dict, List

import questionary

try:
    from miwear import __version__
except ImportError:
    __version__ = "0.0.1"


def select_interactive(items: List[str], message: str = "Select:") -> int:
    """Arrow-key selector backed by questionary. Returns chosen index."""
    answer = questionary.select(message, choices=items).ask()
    if answer is None:
        raise SystemExit(1)
    return items.index(answer)


def find_zip_file(path: str) -> str:
    """Find a zip file in the given directory. Prompt user if multiple."""
    zip_files = sorted(glob.glob(os.path.join(path, "*.zip")))
    if not zip_files:
        print(f"No ZIP files found in '{os.path.abspath(path)}'.")
        raise SystemExit(1)
    if len(zip_files) == 1:
        print(f"Found: {os.path.basename(zip_files[0])}")
        return zip_files[0]

    names = [os.path.basename(f) for f in zip_files]
    idx = select_interactive(names, f"Found {len(zip_files)} ZIP files:")
    print(f"Selected: {names[idx]}")
    return zip_files[idx]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract files from a ZIP archive into the current directory, "
        "filtered by a precise filename-stem suffix (e.g. 'ap' matches "
        "'*ap.elf' but not '*app.elf'). Use 'all' to extract everything."
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "target",
        type=str,
        nargs="?",
        default="ap",
        help="Filename-stem suffix to match precisely, e.g. 'ap' selects "
        "'*ap.elf' but not '*app.elf'; 'all' extracts every file "
        "(default: ap)",
    )
    parser.add_argument(
        "zipfile",
        type=str,
        nargs="?",
        default=None,
        help="Path to the ZIP file (auto-detects in current directory if omitted)",
    )
    parser.add_argument(
        "-e",
        "--ext",
        type=str,
        nargs="+",
        default=["elf"],
        help="File extensions to extract (default: elf)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=".",
        help="Output directory (default: current directory)",
    )

    args = parser.parse_args()

    if args.zipfile is None:
        args.zipfile = find_zip_file(".")
    elif not os.path.isfile(args.zipfile):
        print(f"Error: '{args.zipfile}' does not exist or is not a file.")
        return

    # Normalize extensions (strip leading dots) and the target stem suffix.
    extensions: List[str] = [ext.lstrip(".").lower() for ext in args.ext]
    target: str = args.target.lower()
    extract_all: bool = target == "all"

    def matches(name: str) -> bool:
        if name.endswith("/"):
            return False
        ext_ok = name.rsplit(".", 1)[-1].lower() in extensions
        if extract_all:
            # 'all' restores the legacy behavior: every file matching --ext,
            # plus the OTA package regardless of its extension.
            return ext_ok or os.path.basename(name) == "ota.zip"
        # Precise stem-suffix match: target 'ap' selects '*ap.elf' but NOT
        # '*app.elf', because 'app'.endswith('ap') is False.
        stem = os.path.splitext(os.path.basename(name))[0]
        return ext_ok and stem.endswith(target)

    def selection_desc() -> str:
        if extract_all:
            return f"extension(s) {', '.join('.' + e for e in extensions)}"
        return f"stem suffix '{target}' (e.g. '*{target}.{extensions[0]}')"

    try:
        with zipfile.ZipFile(args.zipfile, "r") as zf:
            matched = [name for name in zf.namelist() if matches(name)]

            if not matched:
                print(
                    f"No files matching {selection_desc()} found in '{args.zipfile}'."
                )
                return

            # Group by basename to detect same-name conflicts across folders.
            groups: Dict[str, List[str]] = defaultdict(list)
            for name in matched:
                groups[os.path.basename(name)].append(name)

            # Sort key: place the "base" parent dir first (no '_' suffix
            # variant like 'audio' before 'audio_test'/'audio_performance_test').
            def conflict_sort_key(path: str) -> tuple:
                parent = os.path.basename(os.path.dirname(path))
                return (parent.count("_"), len(parent), parent)

            selected: List[str] = []
            for basename, names in groups.items():
                if len(names) == 1:
                    selected.append(names[0])
                    continue
                names.sort(key=conflict_sort_key)
                idx = select_interactive(
                    names,
                    f"'{basename}' exists in {len(names)} locations:",
                )
                print(f"Selected: {names[idx]}")
                selected.append(names[idx])

            os.makedirs(args.output, exist_ok=True)

            print(
                f"\nExtracting {len(selected)} file(s) matching "
                f"{selection_desc()} "
                f"to '{os.path.abspath(args.output)}':"
            )

            for name in selected:
                basename = os.path.basename(name)
                target = os.path.join(args.output, basename)
                with zf.open(name) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                print(f"  {basename}  (from {name})")

            print("Done!")

    except zipfile.BadZipFile:
        print(f"Error: '{args.zipfile}' is not a valid ZIP file.")
    except PermissionError:
        print(f"Error: Permission denied for '{args.zipfile}'.")
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
