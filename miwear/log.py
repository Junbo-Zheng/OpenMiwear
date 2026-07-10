#!/usr/bin/env python3
# -*- coding:UTF-8 -*-
#
# Copyright (C) 2023 Junbo Zheng. All rights reserved.
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

import shutil
import subprocess
import sys
import os
import gzip
import glob
import re
import tarfile
import logging

import argparse
from enum import IntEnum
from typing import List, Optional

try:
    from miwear import __version__
except ImportError:
    __version__ = "0.0.1"

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.DEBUG,
    datefmt="%Y-%m-%d %H:%M:%S",
    format="%(asctime)-19s.%(msecs)03d %(levelname)-8s %(filename)s %(lineno)-3d %(process)d %(message)s",
)


class DefaultCLIParameters:
    remote_path = "/sdcard/Android/data/com.mi.health/files/log/devicelog"
    source_path = "."
    output_path = "./file"
    output_file = "file.tar.gz"
    file_name = "log.tar.gz"
    filter_pattern = "log\\d*|tmp.log|last.log"
    tmp_log = "tmp.log"
    special_file_suffix = [".core", ".txt"]


def _chmod_recursive(path: str, mode: int = 0o755) -> None:
    """Recursively set permissions on a directory tree."""
    for root, dirs, files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), mode)
        for f in files:
            os.chmod(os.path.join(root, f), mode)


class CLIParametersParser:
    def __init__(self) -> None:
        arg_parser = argparse.ArgumentParser(
            description="Extract a file with the suffix `.tar.gz` from the source path or remote path and extract to "
            "output_path."
        )

        arg_parser.add_argument(
            "--version",
            action="version",
            version=f"%(prog)s {__version__}",
        )

        arg_parser.add_argument(
            "-o",
            "--output_path",
            type=str,
            nargs="+",
            default=DefaultCLIParameters.output_path,
            help="extract packet output path",
        )

        arg_parser.add_argument(
            "-m",
            "--merge_file",
            type=str,
            nargs="?",
            help="extract packet and merge to a new file",
        )
        arg_parser.add_argument(
            "-f",
            "--filename",
            type=str,
            nargs="?",
            default=None,
            help="extract file path (with full path or just filename), such as: /path/to/log.tar.gz or log.tar.gz",
        )
        arg_parser.add_argument(
            "file_path",
            type=str,
            nargs="?",
            default=None,
            help="extract packet file path (positional argument), alternative to -f option",
        )
        arg_parser.add_argument(
            "--phone",
            action="store_true",
            help="pull file from Android phone via adb",
        )
        arg_parser.add_argument(
            "-p",
            "--purge_source_file",
            help="purge source file if is true",
            action="store_true",
            default=False,
        )
        arg_parser.add_argument(
            "-F",
            "--filter_pattern",
            type=str,
            default=DefaultCLIParameters.filter_pattern,
            help="filter the files to be merged",
        )
        arg_parser.add_argument(
            "-l",
            "--log",
            type=str,
            default=DefaultCLIParameters.tmp_log,
            help="special log file name(default: tmp.log)",
        )

        if (len(sys.argv)) <= 1:
            arg_parser.print_help()
            sys.exit(0)

        cli_args = arg_parser.parse_args()

        if cli_args.filename is not None:
            input_str = cli_args.filename
        elif cli_args.file_path is not None:
            input_str = cli_args.file_path
        else:
            arg_parser.error(
                "must provide file path via -f/--filename option or positional argument"
            )
            sys.exit(1)

        # Store all needed values as simple instance attributes
        self.output_path: str = cli_args.output_path
        self.phone: bool = cli_args.phone
        self.purge_source_file: bool = cli_args.purge_source_file
        self.filter_pattern: str = cli_args.filter_pattern
        self.log_name: str = cli_args.log
        self.merge_file: Optional[str] = cli_args.merge_file

        if os.path.dirname(input_str):
            self.source_path: List[str] = [os.path.dirname(os.path.abspath(input_str))]
            self.filename: List[str] = [os.path.basename(input_str)]
        else:
            self.source_path = [os.getcwd()]
            self.filename = [input_str]

        base_name = self.filename[0]
        if re.search(r"\d+", base_name):
            numbers = re.findall(r"\d+", base_name)
            logger.debug(f"filename number -> {numbers}")
            if numbers:
                base_name = numbers[0]
                logger.debug(
                    f"Extracted number '{base_name}' from input '{self.filename[0]}'"
                )

            if len(numbers) > 1:
                self.merge_file = os.path.join(os.getcwd(), numbers[-2] + ".log")
        else:
            pattern = r"^(.*?)\.tar.*\.gz$"
            match = re.match(pattern, base_name)
            if match:
                base_name = match.group(1)

        # With the input filename parameter as merge file if merge file is not specified
        if self.merge_file is None:
            self.merge_file = os.path.join(os.getcwd(), base_name + ".log")

        logger.debug("output_path      :%s", self.output_path)
        logger.debug("source_path      :%s", self.source_path)
        logger.debug("filename         :%s", self.filename)
        logger.debug("purge_source_file:%s", self.purge_source_file)
        logger.debug("merge_file       :%s", self.merge_file)


class LogTools:
    def __init__(self, cli_parser: CLIParametersParser) -> None:
        self.__cli_parser = cli_parser
        self.log_packet_path: Optional[str] = None
        self.log_dir_path: Optional[str] = None

    def clear_output_dir(self, ask: bool = True) -> int:
        if not os.path.exists(self.__cli_parser.output_path):
            return 0

        # if output path exists, clear
        if ask:
            input_str = input(
                "The %s already exists, will cover it? [Y/N]\n"
                % self.__cli_parser.output_path
            )
            if input_str != "Y":
                logger.debug("quit and exit")
                return -1
        # fmt: off
        logger.debug(
            Highlight.Convert("clear") + " exist file %s",
            self.__cli_parser.output_path,
        )
        # fmt: on
        shutil.rmtree(self.__cli_parser.output_path, ignore_errors=True)
        return 0

    def pull_packet(self) -> int:
        if self.__cli_parser.phone:
            adb_cmd = "adb pull " + DefaultCLIParameters.remote_path + " ./"
            logger.debug(adb_cmd)
            subprocess.run(
                adb_cmd,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=subprocess.PIPE,
                shell=True,
            )

            filename = self.__cli_parser.filename[0]
            file = os.getcwd() + "/devicelog/**/" + "*" + filename + "*.tar*.gz"
            result = glob.glob(file, recursive=True)
        else:
            filename = self.__cli_parser.filename[0]
            if ".tar" in filename and ".gz" in filename:
                file_path = os.path.join(self.__cli_parser.source_path[0], filename)
                result = [file_path] if os.path.exists(file_path) else []
            else:
                pattern = (
                    self.__cli_parser.source_path[0]
                    + "/"
                    + "*"
                    + filename
                    + "*.tar*.gz"
                )
                result = glob.glob(pattern)

        if len(result) == 0:
            logger.error(
                Highlight.Convert(
                    f"Not found file packet, please check source path: {self.__cli_parser.source_path}",
                    Highlight.RED,
                )
            )
            return -1

        # fmt: off
        logger.debug(
            Highlight.Convert("pull") + " %s from %s",
            result,
            self.__cli_parser.source_path[0]
        )
        # fmt: on
        if len(result) > 1:
            index = input("Please input the file index you want to extract:\n")
            file = result[int(index)]
        else:
            file = result[0]

        path = os.path.dirname(file)
        filename_base = self.__cli_parser.filename[0]
        if ".tar.gz" in filename_base:
            filename_base = (
                filename_base.replace(".tar.gz", "")
                .replace(".tar", "")
                .replace(".gz", "")
            )
        elif ".tar" in filename_base:
            filename_base = filename_base.replace(".tar", "").replace(".gz", "")
        elif ".gz" in filename_base:
            filename_base = filename_base.replace(".gz", "")
        output = filename_base + "_" + DefaultCLIParameters.output_file
        output = os.path.join(path, output)

        if self.__cli_parser.purge_source_file:
            logger.debug("rename to %s", output)
            os.rename(file, output)
        else:
            logger.debug("copy to %s", output)
            shutil.copyfile(file, output)
        if output is None:
            logger.error(
                Highlight.Convert(f"Not found file packet in {file}", Highlight.RED)
            )
            return -1

        self.log_packet_path = output

        logger.debug("output file %s", self.log_packet_path)
        return 0

    def __find_logfiles_path__(self) -> int:
        # Candidate anchor filenames used to locate the log directory. The
        # configured log name (default tmp.log) is tried first; last.log is an
        # automatic fallback for projects that renamed tmp.log to last.log.
        candidates: List[str] = []
        for name in (self.__cli_parser.log_name, "last.log"):
            if name and name not in candidates:
                candidates.append(name)

        for root, dirs, files in os.walk(self.__cli_parser.output_path):
            for file in files:
                if file in candidates:
                    self.log_dir_path = os.path.abspath(root)
                    logger.debug(
                        "located log dir by anchor '%s' at %s",
                        file,
                        self.log_dir_path,
                    )
                    return 0

        # Neither tmp.log nor last.log found. Fall back to a directory holding
        # rotated .gz logs so the remaining files can still be gunzipped/merged.
        gz_dir = self.__find_gz_dir__()
        if gz_dir is not None:
            self.log_dir_path = gz_dir
            logger.warning(
                Highlight.Convert(
                    "Not found tmp.log or last.log in the archive; falling "
                    "back to rotated logs in %s. The current-log file will be "
                    "absent from the merge output." % gz_dir,
                    Highlight.YELLOW,
                )
            )
            return 0

        logger.warning(
            Highlight.Convert(
                "Not found tmp.log or last.log (and no rotated .gz logs "
                "either); skipping log localization and merge. If your "
                "project uses a different current-log name, pass it via "
                "-l/--log.",
                Highlight.YELLOW,
            )
        )
        return -1

    def __find_gz_dir__(self) -> Optional[str]:
        """Pick the directory under output_path containing the most .gz files.

        Used as a fallback anchor when neither tmp.log nor last.log exists, so
        rotated gzipped logs can still be processed.
        """
        best_dir: Optional[str] = None
        best_count = 0
        for root, dirs, files in os.walk(self.__cli_parser.output_path):
            gz_count = sum(1 for f in files if f.endswith(".gz"))
            if gz_count > best_count:
                best_count = gz_count
                best_dir = os.path.abspath(root)
        return best_dir

    def __find_special_files(self) -> List[str]:
        if self.log_dir_path is None:
            return []
        special_files: List[str] = []
        for root, dirs, files in os.walk(self.log_dir_path):
            for file in files:
                # Check if the file ends with any suffix in special_file_suffix
                for suffix in DefaultCLIParameters.special_file_suffix:
                    if file.lower().endswith(suffix.lower()):
                        special_files.append(os.path.join(root, file))
        return special_files

    def __remove_all_suffix_gz_file__(self) -> int:
        if self.log_dir_path is None:
            return 0
        for root, dirs, files in os.walk(self.log_dir_path):
            for file in files:
                if os.path.splitext(file)[-1] == ".gz":
                    os.remove(os.path.join(root, file))
        return 0

    def __gunzip_all__(self) -> int:
        if self.log_dir_path is None:
            logger.debug("no log dir located, skip gunzip")
            return 0
        if not os.path.exists(self.log_dir_path):
            logger.error(
                Highlight.Convert(
                    f"Not found log directory: {self.log_dir_path}", Highlight.RED
                )
            )
            return -1

        dirs = os.listdir(self.log_dir_path)
        for file in dirs:
            if ".gz" in file:
                try:
                    filename = file.replace(".gz", "")
                    gzip_file_path = os.path.join(self.log_dir_path, file)
                    output_file_path = os.path.join(self.log_dir_path, filename)

                    with gzip.open(gzip_file_path, "rb") as gzip_file:
                        with open(output_file_path, "wb+") as f:
                            f.write(gzip_file.read())

                except EOFError as e:
                    logger.error(f"file {file} maybe error, code: {e}")
                    continue
                except Exception as e:
                    logger.error(f"file {file} error: {e}")
                    continue
        logger.debug(Highlight.Convert("gunzip") + " all done")
        return 0

    def extract_special_files(self) -> int:
        special_files = self.__find_special_files()
        if not special_files:
            logger.debug("No special files found")
            return 0

        logger.debug("Special files found:")
        for special_file in special_files:
            logger.debug(f"  -> {special_file}")
            des_path = os.path.join(os.getcwd(), os.path.basename(special_file))
            logger.debug(f"Copying {special_file} to {des_path}")
            shutil.copy(special_file, des_path)
        return 0

    def __is_gzip_file__(self, filepath: str) -> bool:
        try:
            with open(filepath, "rb") as f:
                magic = f.read(2)
                return magic == b"\x1f\x8b"  # gzip magic bytes
        except Exception:
            return False

    def extract_packet(self) -> int:
        if not os.path.exists(self.__cli_parser.output_path):
            os.makedirs(self.__cli_parser.output_path)

        assert self.log_packet_path is not None

        if self.__is_gzip_file__(self.log_packet_path):
            # Decompress gzip using Python stdlib
            logger.debug(
                Highlight.Convert("gzip") + " decompress " + self.log_packet_path
            )
            tar_package = self.log_packet_path.replace(".gz", "")
            try:
                with gzip.open(self.log_packet_path, "rb") as f_in:
                    with open(tar_package, "wb") as f_out:
                        f_out.write(f_in.read())
                os.remove(self.log_packet_path)
            except Exception as e:
                logger.error(
                    Highlight.Convert(f"gzip decompress failed: {e}", Highlight.RED)
                )
                return -1
        else:
            logger.debug(
                Highlight.Convert("skip gzip")
                + " - file is not gzip compressed, treating as tar archive"
            )
            tar_package = self.log_packet_path

        # Extract tar using Python stdlib
        logger.debug(Highlight.Convert("tar") + " extract " + tar_package)
        try:
            with tarfile.open(tar_package) as tar:
                # Strip leading '/' to match `tar -xvf`'s default behavior;
                # otherwise absolute member paths escape output_path via
                # os.path.join() and hit "Permission denied" at the FS root.
                for member in tar.getmembers():
                    member.name = member.name.lstrip("/")
                tar.extractall(self.__cli_parser.output_path)
        except tarfile.TarError as e:
            logger.error(Highlight.Convert(f"tar extract failed: {e}", Highlight.RED))
            return -1

        _chmod_recursive(self.__cli_parser.output_path)

        if (
            tar_package != self.log_packet_path
            or not self.__cli_parser.purge_source_file
        ):
            os.remove(tar_package)

        # find log files dir path; tolerant of missing tmp.log/last.log
        # (falls back to rotated .gz logs, or skips with a warning)
        self.__find_logfiles_path__()

        # gunzip all *.gz files under path
        if self.__gunzip_all__() != 0:
            return -1

        # remove unused .gz files
        return self.__remove_all_suffix_gz_file__()

    # merge all file to a new file
    def merge_logfiles(self) -> bool:
        if self.log_dir_path is None:
            return False
        assert self.__cli_parser.merge_file is not None
        file_list = os.listdir(self.log_dir_path)
        file_list.sort(key=lambda name: (len(name), name))
        logger.debug(Highlight.Convert("merge") + " file list %s", file_list)

        if os.path.exists(self.__cli_parser.merge_file):
            logger.debug("merge file exist, will remove")
            os.remove(self.__cli_parser.merge_file)

        files_to_merge: List[str] = []
        for file in file_list:
            if re.match(self.__cli_parser.filter_pattern, file) is None:
                continue
            files_to_merge.append(os.path.join(self.log_dir_path, file))

        if not files_to_merge:
            logger.warning("No files match the pattern to merge")
            return False

        try:
            with open(self.__cli_parser.merge_file, "wb") as outfile:
                for file_path in files_to_merge:
                    logger.debug(f"prepare merge file {file_path}")
                    try:
                        with open(file_path, "rb") as f:
                            outfile.write(f.read())
                    except Exception as e:
                        logger.warning(f"Failed to read {file_path}: {e}")
                        continue

            logger.debug(
                "Successfully merged %d files to %s",
                len(files_to_merge),
                self.__cli_parser.merge_file,
            )
            return True

        except Exception as e:
            logger.error(f"Failed to merge files: {e}")
            return False

    def get_merge_file(self) -> Optional[str]:
        return self.__cli_parser.merge_file

    def merge_txt_files(self) -> bool:
        if self.log_dir_path is None or not os.path.exists(self.log_dir_path):
            logger.warning("Log directory not found, skip merging txt files")
            return False

        assert self.__cli_parser.merge_file is not None

        txt_files: List[str] = []
        for root, dirs, files in os.walk(self.log_dir_path):
            for file in files:
                if file.lower().startswith("crash") and file.lower().endswith(".txt"):
                    txt_files.append(os.path.join(root, file))

        if not txt_files:
            logger.debug("No crash txt files found to merge")
            return False

        txt_files.sort()
        logger.debug(Highlight.Convert("merge crash txt") + " file list %s", txt_files)

        merge_file_base = os.path.splitext(self.__cli_parser.merge_file)[0]
        txt_merge_file = merge_file_base + ".txt"

        if os.path.exists(txt_merge_file):
            logger.debug("txt merge file exists, will remove")
            os.remove(txt_merge_file)

        try:
            with open(txt_merge_file, "wb") as outfile:
                for file_path in txt_files:
                    logger.debug(f"prepare merge crash txt file {file_path}")
                    try:
                        with open(file_path, "rb") as f:
                            outfile.write(f.read())
                    except Exception as e:
                        logger.warning(f"Failed to read {file_path}: {e}")
                        continue

            logger.debug(
                "Successfully merged %d crash txt files to %s",
                len(txt_files),
                txt_merge_file,
            )
            return True

        except Exception as e:
            logger.error(f"Failed to merge crash txt files: {e}")
            return False


def check_error_exit(ret: int) -> None:
    if ret:
        logger.error(
            Highlight.Convert("Extraction failed with code: " + str(ret), Highlight.RED)
        )
        exit(ret)


class Highlight(IntEnum):
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLOW = 33
    BLUE = 34
    WHITE = 37

    @staticmethod
    def Convert(msg: str, color: int = 34) -> str:  # 34 = BLUE
        if not sys.stderr.isatty():
            return str(msg)
        return "\033[;%dm%s\033[0m" % (color, msg)


def main() -> None:
    cli_args = CLIParametersParser()
    logtools = LogTools(cli_args)

    # clear exist output dir
    check_error_exit(logtools.clear_output_dir())

    # pull log packet from phone or local, depends on command line parameters
    check_error_exit(logtools.pull_packet())

    # extract log packet
    check_error_exit(logtools.extract_packet())

    # extract special file
    check_error_exit(logtools.extract_special_files())

    # merge the log files to one file, then remove output dir
    merge_success = logtools.merge_logfiles()

    # merge crash txt files before removing output dir
    txt_merge_success = logtools.merge_txt_files()
    if txt_merge_success is True:
        merge_file = logtools.get_merge_file()
        assert merge_file is not None
        merge_file_base = os.path.splitext(merge_file)[0]
        txt_merge_file = merge_file_base + ".txt"
        logger.debug(
            Highlight.Convert("crash txt", Highlight.GREEN)
            + f" file at [{txt_merge_file}]"
        )

    if merge_success is True:
        logtools.clear_output_dir(False)

    logger.debug(Highlight.Convert("Successful", Highlight.GREEN))
    logger.debug(
        f"All done, you can take a look now!(log file at [{logtools.get_merge_file()}])"
    )


if __name__ == "__main__":
    main()
