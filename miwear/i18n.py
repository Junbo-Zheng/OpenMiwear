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

import argparse
import logging
import os
import shutil
import subprocess
from typing import List

try:
    from miwear import __version__
except ImportError:
    __version__ = "0.0.1"

logger = logging.getLogger(__name__)


def find_files(directory: str, ext: str) -> List[str]:
    found: List[str] = []
    for root, _dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(ext):
                found.append(os.path.join(root, file))
    return found


def target_name_for(src_path: str, target_ext: str) -> str:
    # .../<locale>/LC_MESSAGES/messages.mo -> <locale>.po; otherwise <stem>.po
    parent = os.path.basename(os.path.dirname(src_path))
    locale_dir = os.path.basename(os.path.dirname(os.path.dirname(src_path)))
    if parent == "LC_MESSAGES":
        if not locale_dir:
            raise SystemExit(f"cannot derive locale name for {src_path}")
        return f"{locale_dir}{target_ext}"
    return f"{os.path.splitext(os.path.basename(src_path))[0]}{target_ext}"


def convert(
    src_file: str,
    tool: str,
    output_dir: str,
    target_ext: str,
    in_place: bool,
) -> bool:
    if in_place:
        out_file = os.path.splitext(src_file)[0] + target_ext
        if os.path.exists(out_file):
            logger.warning("skip %s: target already exists", out_file)
            return False
    else:
        out_file = os.path.join(output_dir, target_name_for(src_file, target_ext))

    cmd = [tool, src_file, "-o", out_file]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        logger.error("failed to convert %s: %s", src_file, e.stderr.strip())
        return False

    logger.info("%s -> %s", src_file, out_file)
    return True


def run(path: str, output: str, in_place: bool, reverse: bool) -> None:
    if reverse:
        src_ext, target_ext, tool = ".mo", ".po", "msgunfmt"
    else:
        src_ext, target_ext, tool = ".po", ".mo", "msgfmt"

    if shutil.which(tool) is None:
        logger.error("%s not found, install gettext first (apt install gettext)", tool)
        raise SystemExit(1)

    if not os.path.isdir(path):
        logger.error("path not found: %s", path)
        raise SystemExit(1)

    src_files = find_files(path, src_ext)
    if not src_files:
        logger.error("no %s files found under %s", src_ext, path)
        raise SystemExit(1)

    if not in_place:
        seen = set()
        for src_file in src_files:
            name = target_name_for(src_file, target_ext)
            if name in seen:
                logger.error(
                    "duplicate output name %s (from %s), refusing to overwrite",
                    name,
                    src_file,
                )
                raise SystemExit(1)
            seen.add(name)
        os.makedirs(output, exist_ok=True)

    ok = 0
    for src_file in src_files:
        if convert(src_file, tool, output, target_ext, in_place):
            ok += 1

    logger.info(
        "done: %d/%d converted%s",
        ok,
        len(src_files),
        "" if in_place else f", output dir: {output}",
    )
    if ok != len(src_files):
        raise SystemExit(1)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
        format=(
            "%(asctime)-19s.%(msecs)03d %(levelname)-8s "
            "%(filename)s %(lineno)-3d %(process)d %(message)s"
        ),
    )

    parser = argparse.ArgumentParser(
        description="gettext converter: .po -> .mo by default, .mo -> .po with --reverse"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="directory to search for source files, current directory by default",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="output dir (ignored with --in-place), <input_dir>_po/_mo by default",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="write each target file next to its source instead of into --output",
    )
    parser.add_argument(
        "--reverse",
        action="store_true",
        help="convert .mo back to editable .po (default is .po -> .mo)",
    )

    args = parser.parse_args()
    output = args.output
    if output is None:
        base = os.path.basename(os.path.abspath(args.path))
        suffix = "_po" if args.reverse else "_mo"
        output = f"{base}{suffix}"
    run(args.path, output, args.in_place, args.reverse)


if __name__ == "__main__":
    main()
