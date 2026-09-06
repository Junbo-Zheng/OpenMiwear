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

"""OTA delta analyzer.

Unpack two OTA packages, pair their payload images, run ddelta on every pair and
explain where the delta size comes from, as an HTML report with a Markdown mirror.

``--blocksize`` is required: it is the block size your OTA packaging step hands
to ``ddelta_generate`` as its fourth argument. It differs per project, and a
non-zero value switches ddelta to in-place patching, which changes the patch
that comes out. It is recorded in every report so a report can always be
reproduced.

The ddelta toolchain (``ddelta_generate`` / ``ddelta_apply``) is deliberately not
bundled: those are architecture specific binaries owned by another project. Build
them once from the Vela source tree and this tool will find them::

    cd <vela-root>/external/ddelta/ddelta && make clean && make

Lookup order per tool: ``--ddelta`` argument, ``MIWEAR_DDELTA_GENERATE`` /
``MIWEAR_DDELTA_APPLY`` environment variable, ``PATH``, the current directory,
then ``external/ddelta/ddelta`` in the cwd or any parent directory. Without the
tool the analysis still runs, reporting byte level comparison only.

Patch format (``external/ddelta/ddelta/ddelta.h``), all integers big endian::

    struct ddelta_header {          /* 32 bytes */
        char     magic[8];          /* "DDELTA60" */
        uint64_t new_file_size;
        uint64_t old_file_size;
        uint32_t old_file_crc;
        char     padding[4];
    };

    struct ddelta_entry_header {    /* 12 bytes, repeated */
        uint32_t diff;              /* or oldcrc when seek == DDELTA_FLUSH */
        uint32_t extra;             /* or newcrc when seek == DDELTA_FLUSH */
        int32_t  seek;              /* INT32_MIN => flush record */
    };

Each non flush entry is followed by ``diff`` bytes of delta data and ``extra``
bytes of literal data. The stream terminates on an all zero entry.
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import webbrowser
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    from miwear import __version__
except ImportError:  # pragma: no cover - only hit when run from a source tree
    __version__ = "0.0.1"


# ============ ddelta toolchain ============

DDELTA_MAGIC = b"DDELTA60"
HEADER_SIZE = 32
ENTRY_SIZE = 12
DDELTA_FLUSH = -(2**31)  # INT32_MIN

GENERATE_NAME = "ddelta_generate"
APPLY_NAME = "ddelta_apply"

ENV_GENERATE = "MIWEAR_DDELTA_GENERATE"
ENV_APPLY = "MIWEAR_DDELTA_APPLY"

VELA_SUBPATH = os.path.join("external", "ddelta", "ddelta")

BUILD_HINT = (
    "Build it from the Vela source tree:\n"
    "    cd <vela-root>/external/ddelta/ddelta && make clean && make\n"
    "then re-run with --ddelta <path>, or export "
    f"{ENV_GENERATE}=<path>, or add it to PATH."
)


def _search_dirs() -> List[str]:
    """Directories to probe for the ddelta binaries, in priority order."""
    dirs = [os.getcwd()]
    cur = os.path.abspath(os.getcwd())
    while True:
        dirs.append(os.path.join(cur, VELA_SUBPATH))
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return dirs


def _find_tool(
    name: str,
    env_var: str,
    explicit: Optional[str] = None,
    sibling_of: Optional[str] = None,
) -> Optional[str]:
    """Locate a ddelta executable, or return None when unavailable.

    *sibling_of* lets one tool be found next to another already resolved one:
    a single ``make`` builds ddelta_generate and ddelta_apply side by side, so
    pointing at one is enough to find the other.
    """
    if explicit:
        path = os.path.abspath(os.path.expanduser(explicit))
        return path if os.path.isfile(path) and os.access(path, os.X_OK) else None

    env_value = os.environ.get(env_var)
    if env_value:
        path = os.path.abspath(os.path.expanduser(env_value))
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    if sibling_of:
        path = os.path.join(os.path.dirname(os.path.abspath(sibling_of)), name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    found = shutil.which(name)
    if found:
        return os.path.abspath(found)

    for directory in _search_dirs():
        path = os.path.join(directory, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return os.path.abspath(path)

    return None


def find_generate(explicit: Optional[str] = None) -> Optional[str]:
    """Locate ``ddelta_generate``."""
    return _find_tool(GENERATE_NAME, ENV_GENERATE, explicit)


def find_apply(
    explicit: Optional[str] = None, sibling_of: Optional[str] = None
) -> Optional[str]:
    """Locate ``ddelta_apply``, preferring the directory of ``ddelta_generate``."""
    return _find_tool(APPLY_NAME, ENV_APPLY, explicit, sibling_of)


def run_generate(
    tool: str,
    old_file: str,
    new_file: str,
    patch_file: str,
    blocksize: int = 0,
    timeout: int = 600,
) -> Tuple[bool, str]:
    """Run ``ddelta_generate old new patch [blocksize]``.

    Returns ``(True, "")`` on success, ``(False, reason)`` otherwise.
    """
    cmd = [tool, old_file, new_file, patch_file]
    if blocksize > 0:
        cmd.append(str(blocksize))
    return _run(cmd, timeout)


def run_apply(
    tool: str,
    old_file: str,
    target: str,
    patch_file: str,
    timeout: int = 600,
) -> Tuple[bool, str]:
    """Run ``ddelta_apply oldfile newfile|tmpdir patchfile``.

    *target* selects the mode: a regular file path reconstructs the image
    there, while a **directory** switches ddelta_apply to in-place mode, where
    each block is staged in the directory and then written back into
    *old_file* — so the result ends up in *old_file*, not in the directory.
    Patches generated with a non-zero block size only apply correctly in that
    in-place mode.

    ``ddelta_apply`` opens *old_file* read-write in both modes, so always hand
    it a throwaway copy.
    """
    return _run([tool, old_file, target, patch_file], timeout)


def _run(cmd: List[str], timeout: int) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    except OSError as exc:
        return False, str(exc)

    if proc.returncode == 0:
        return True, ""

    reason = (proc.stderr or proc.stdout or "").strip()
    return False, reason or f"exit code {proc.returncode}"


@dataclass
class PatchInfo:
    """Structural breakdown of a ddelta patch file."""

    fmt: str = "unknown"
    total_size: int = 0
    header_size: int = 0
    ctrl_size: int = 0
    diff_size: int = 0
    extra_size: int = 0
    entry_count: int = 0
    flush_count: int = 0
    new_file_size: int = 0
    old_file_size: int = 0
    old_file_crc: int = 0
    truncated: bool = False


def parse_patch(patch_file: str) -> PatchInfo:
    """Parse a ddelta patch file into a :class:`PatchInfo`.

    Unknown or malformed patches are reported with ``fmt="unknown"`` instead of
    raising, so a single odd file never aborts a whole run.
    """
    total = os.path.getsize(patch_file)
    info = PatchInfo(total_size=total)

    with open(patch_file, "rb") as f:
        header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            info.truncated = True
            return info

        magic, new_size, old_size, old_crc = struct.unpack(">8sQQI4x", header)
        if magic != DDELTA_MAGIC:
            return info

        info.fmt = magic.decode("ascii")
        info.header_size = HEADER_SIZE
        info.new_file_size = new_size
        info.old_file_size = old_size
        info.old_file_crc = old_crc

        while True:
            raw = f.read(ENTRY_SIZE)
            if len(raw) < ENTRY_SIZE:
                info.truncated = True
                break

            diff, extra, seek = struct.unpack(">IIi", raw)
            info.ctrl_size += ENTRY_SIZE

            if diff == 0 and extra == 0 and seek == 0:
                break  # end of stream

            if seek == DDELTA_FLUSH:
                info.flush_count += 1  # diff/extra are crc32 values here
                continue

            info.entry_count += 1
            info.diff_size += diff
            info.extra_size += extra

            if f.seek(diff + extra, os.SEEK_CUR) > total:
                info.truncated = True
                break

    return info


# ============ Analysis ============

CHUNK_SIZE = 4096
SPARSE_RATIO = 0.9  # a chunk with >90% zero bytes counts as sparse
DENSE_RATIO = 0.1
MAX_REGIONS = 10  # detailed change regions kept per file


@dataclass
class Region:
    """A single changed chunk of a file."""

    offset: int
    size: int
    changed_bytes: int

    @property
    def change_ratio(self) -> float:
        return self.changed_bytes / self.size if self.size else 0.0


@dataclass
class CompareResult:
    """Chunk-wise comparison result for one pair of files."""

    old_size: int = 0
    new_size: int = 0
    changed_bytes: int = 0
    change_ratio: float = 0.0
    region_count: int = 0
    zero_to_data: int = 0
    data_to_zero: int = 0
    content_change: int = 0
    regions: List[Region] = field(default_factory=list)


@dataclass
class FileDiff:
    """Diff result for one payload file present in both packages."""

    name: str
    old_size: int = 0
    new_size: int = 0
    patch_size: int = 0
    changed_bytes: int = 0
    change_ratio: float = 0.0
    region_count: int = 0
    zero_to_data: int = 0
    data_to_zero: int = 0
    content_change: int = 0
    regions: List[Region] = field(default_factory=list)
    patch_info: Optional[PatchInfo] = None
    patch_file: Optional[str] = None
    compressed_size: int = 0
    error: Optional[str] = None
    verified: Optional[bool] = None

    @property
    def size_diff(self) -> int:
        return self.new_size - self.old_size

    @property
    def patch_ratio(self) -> float:
        """Raw (uncompressed) patch size relative to the new file size."""
        return self.patch_size / self.new_size if self.new_size else 0.0

    @property
    def compressed_ratio(self) -> float:
        """Deflated patch size relative to the new file size.

        ddelta emits uncompressed patches on purpose, so this is the ratio that
        actually reflects OTA download cost.
        """
        return self.compressed_size / self.new_size if self.new_size else 0.0

    @property
    def severity(self) -> str:
        """Coarse change level used for report badges."""
        if self.change_ratio > 0.5:
            return "high"
        if self.change_ratio > 0.2:
            return "medium"
        return "low"


@dataclass
class BundleEntry:
    """One patch inside the deflated delta bundle."""

    name: str
    new_size: int
    patch_size: int
    compressed_size: int

    @property
    def compression_ratio(self) -> float:
        """Fraction of the raw patch removed by deflating it."""
        if not self.patch_size:
            return 0.0
        return 1.0 - self.compressed_size / self.patch_size


@dataclass
class ZipAnalysis:
    """Compression statistics for the bundle of generated patches."""

    zip_path: str
    zip_size: int = 0
    total_original_size: int = 0
    entries: List[BundleEntry] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        return len(self.entries)

    @property
    def compression_ratio(self) -> float:
        """Fraction of space saved by deflating the patches."""
        if not self.total_original_size:
            return 0.0
        return 1.0 - self.zip_size / self.total_original_size


@dataclass
class Analysis:
    """Full result of comparing two OTA packages."""

    old_package: str
    new_package: str
    results: List[FileDiff] = field(default_factory=list)
    only_in_old: List[str] = field(default_factory=list)
    only_in_new: List[str] = field(default_factory=list)
    extensions: Set[str] = field(default_factory=set)
    ddelta_tool: Optional[str] = None
    blocksize: int = 0
    zip_analysis: Optional[ZipAnalysis] = None

    @property
    def blocksize_text(self) -> str:
        """Human readable blocksize, spelling out what 0 and n/a mean."""
        if not self.ddelta_tool:
            return "不适用（未生成 patch）"
        if not self.blocksize:
            return "0（未传块大小，非原地打补丁）"
        return f"{format_size_mb(self.blocksize)} ({self.blocksize:,} 字节)"

    @property
    def total_old_size(self) -> int:
        return sum(r.old_size for r in self.results)

    @property
    def total_new_size(self) -> int:
        return sum(r.new_size for r in self.results)

    @property
    def total_patch_size(self) -> int:
        return sum(r.patch_size for r in self.results)

    @property
    def total_changed_bytes(self) -> int:
        return sum(r.changed_bytes for r in self.results)

    @property
    def total_patch_ratio(self) -> float:
        return (
            self.total_patch_size / self.total_new_size if self.total_new_size else 0.0
        )

    @property
    def bundle_ratio(self) -> float:
        """Deflated delta bundle size relative to the new package payload."""
        if not self.zip_analysis or not self.total_new_size:
            return 0.0
        return self.zip_analysis.zip_size / self.total_new_size


# ============ Extraction ============


def _is_within(base: str, target: str) -> bool:
    base = os.path.abspath(base)
    target = os.path.abspath(target)
    return target == base or target.startswith(base + os.sep)


def extract_package(path: str, dest: str) -> str:
    """Unpack an OTA package into *dest* and return the directory holding it.

    Accepts ``.zip``, ``.tar``/``.tar.gz``/``.tgz`` archives and plain
    directories (handy for comparing two build output trees directly).
    Archive members escaping *dest* are skipped instead of being written.
    """
    if os.path.isdir(path):
        return path

    os.makedirs(dest, exist_ok=True)
    lower = path.lower()

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            members = [
                m for m in zf.namelist() if _is_within(dest, os.path.join(dest, m))
            ]
            zf.extractall(dest, members=members)
        return dest

    if lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2")):
        with tarfile.open(path) as tf:
            safe = [
                m
                for m in tf.getmembers()
                if _is_within(dest, os.path.join(dest, m.name))
            ]
            tf.extractall(dest, members=safe)
        return dest

    raise ValueError(f"unsupported package format: {path}")


def collect_files(root: str, extensions: Set[str]) -> Dict[str, str]:
    """Map basename -> path for every file under *root* matching *extensions*.

    An empty *extensions* set matches every file.  When two files share a
    basename the shallowest one wins, keeping pairing deterministic.
    """
    found: Dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            ext = os.path.splitext(name)[1].lstrip(".").lower()
            if extensions and ext not in extensions:
                continue
            full = os.path.join(dirpath, name)
            previous = found.get(name)
            if previous is None or full.count(os.sep) < previous.count(os.sep):
                found[name] = full
    return found


# ============ Byte level comparison ============


def _changed_bytes(a: bytes, b: bytes) -> int:
    """Count differing bytes between two equally sized buffers.

    Uses a big-int XOR so the heavy lifting happens in C rather than in a
    Python loop; this is what makes multi-megabyte images tolerable.
    """
    if a == b:
        return 0
    size = len(a)
    xor = int.from_bytes(a, "big") ^ int.from_bytes(b, "big")
    return size - xor.to_bytes(size, "big").count(0)


def compare_files(
    old_file: str, new_file: str, chunk_size: int = CHUNK_SIZE
) -> CompareResult:
    """Chunk-wise comparison of two files.

    Classifies each differing chunk as sparse fill (zeros -> data), data clear
    (data -> zeros) or in-place content change, which is what explains most
    unexpected delta growth in firmware images.  Bytes past the end of the
    shorter file are compared against zeros, so an appended or removed tail
    counts as changed data instead of being silently dropped.
    """
    with open(old_file, "rb") as f:
        old_data = f.read()
    with open(new_file, "rb") as f:
        new_data = f.read()

    result = CompareResult(old_size=len(old_data), new_size=len(new_data))
    max_size = max(result.old_size, result.new_size)
    pad = bytes(chunk_size)

    for offset in range(0, max_size, chunk_size):
        old_chunk = old_data[offset : offset + chunk_size]
        new_chunk = new_data[offset : offset + chunk_size]
        span = max(len(old_chunk), len(new_chunk))
        if not span:
            continue

        # Pad the shorter side with zeros so appended/removed tails are counted
        old_chunk = old_chunk + pad[: span - len(old_chunk)]
        new_chunk = new_chunk + pad[: span - len(new_chunk)]

        if old_chunk == new_chunk:
            continue

        delta = _changed_bytes(old_chunk, new_chunk)
        result.changed_bytes += delta
        result.region_count += 1
        if len(result.regions) < MAX_REGIONS:
            result.regions.append(Region(offset=offset, size=span, changed_bytes=delta))

        old_zero = old_chunk.count(0) / span
        new_zero = new_chunk.count(0) / span
        if old_zero > SPARSE_RATIO and new_zero < DENSE_RATIO:
            result.zero_to_data += span
        elif old_zero < DENSE_RATIO and new_zero > SPARSE_RATIO:
            result.data_to_zero += span
        else:
            result.content_change += span

    result.change_ratio = result.changed_bytes / max_size if max_size else 0.0
    return result


# ============ Patch bundling ============


def bundle_patches(results: List[FileDiff], zip_path: str) -> ZipAnalysis:
    """Deflate every generated patch into one zip and report per-file savings.

    ddelta writes uncompressed patches on purpose (they are meant to be stored
    in a compressed archive), so the deflated size is the only figure that maps
    to an actual OTA download.  The per-file deflated size is written back onto
    each :class:`FileDiff`.
    """
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in results:
            if r.patch_file and os.path.exists(r.patch_file):
                zf.write(r.patch_file, f"{r.name}.patch")

    by_patch_name = {f"{r.name}.patch": r for r in results}
    analysis = ZipAnalysis(zip_path=zip_path, zip_size=os.path.getsize(zip_path))

    with zipfile.ZipFile(zip_path) as zf:
        for meta in zf.infolist():
            diff = by_patch_name.get(meta.filename)
            if diff is not None:
                diff.compressed_size = meta.compress_size
            analysis.entries.append(
                BundleEntry(
                    name=meta.filename,
                    new_size=diff.new_size if diff else 0,
                    patch_size=meta.file_size,
                    compressed_size=meta.compress_size,
                )
            )

    analysis.total_original_size = sum(e.patch_size for e in analysis.entries)
    analysis.entries.sort(key=lambda e: e.compressed_size, reverse=True)
    return analysis


# ============ Orchestration ============


def analyze(
    old_package: str,
    new_package: str,
    work_dir: str,
    patch_dir: str,
    extensions: Set[str],
    ddelta_tool: Optional[str] = None,
    apply_tool: Optional[str] = None,
    blocksize: int = 0,
    verbose: bool = True,
) -> Analysis:
    """Compare two OTA packages end to end.

    When *ddelta_tool* is ``None`` the byte level comparison still runs, so the
    report degrades gracefully instead of failing outright.
    """
    old_dir = os.path.join(work_dir, "old")
    new_dir = os.path.join(work_dir, "new")

    if verbose:
        print("\n[步骤1] 解压OTA包...")
    old_root = extract_package(old_package, old_dir)
    new_root = extract_package(new_package, new_dir)

    if verbose:
        print("\n[步骤2] 查找并配对镜像文件...")
    old_map = collect_files(old_root, extensions)
    new_map = collect_files(new_root, extensions)
    common = sorted(set(old_map) & set(new_map))
    only_old = sorted(set(old_map) - set(new_map))
    only_new = sorted(set(new_map) - set(old_map))

    if verbose:
        print(
            f"  配对成功: {len(common)}个, 仅旧版本: {len(only_old)}个, 仅新版本: {len(only_new)}个"
        )

    analysis = Analysis(
        old_package=old_package,
        new_package=new_package,
        only_in_old=only_old,
        only_in_new=only_new,
        extensions=extensions,
        ddelta_tool=ddelta_tool,
        blocksize=blocksize,
    )

    if verbose:
        print("\n[步骤3] 执行差分分析...")
    os.makedirs(patch_dir, exist_ok=True)

    for name in common:
        old_file = old_map[name]
        new_file = new_map[name]
        stats = compare_files(old_file, new_file)

        diff = FileDiff(
            name=name,
            old_size=stats.old_size,
            new_size=stats.new_size,
            changed_bytes=stats.changed_bytes,
            change_ratio=stats.change_ratio,
            region_count=stats.region_count,
            zero_to_data=stats.zero_to_data,
            data_to_zero=stats.data_to_zero,
            content_change=stats.content_change,
            regions=stats.regions,
        )

        if ddelta_tool:
            patch_file = os.path.join(patch_dir, f"{name}.patch")
            ok, reason = run_generate(
                ddelta_tool, old_file, new_file, patch_file, blocksize
            )
            if ok:
                diff.patch_file = patch_file
                diff.patch_size = os.path.getsize(patch_file)
                diff.patch_info = parse_patch(patch_file)
                if apply_tool:
                    # A blocked patch (more than one flush record) must be
                    # applied in place; this is per patch, not per run.
                    diff.verified = _verify(
                        apply_tool,
                        patch_file,
                        old_file,
                        new_file,
                        work_dir,
                        in_place=diff.patch_info.flush_count > 1,
                    )
            else:
                diff.error = reason
        analysis.results.append(diff)

        if verbose:
            _print_progress(diff)

    return analysis


def _same_content(left: str, right: str, chunk: int = 1 << 20) -> bool:
    """Stream-compare two files without loading them fully into memory."""
    if os.path.getsize(left) != os.path.getsize(right):
        return False
    with open(left, "rb") as a, open(right, "rb") as b:
        while True:
            block_a = a.read(chunk)
            if block_a != b.read(chunk):
                return False
            if not block_a:
                return True


def _verify(
    apply_tool: str,
    patch_file: str,
    old_file: str,
    new_file: str,
    work_dir: str,
    in_place: bool,
) -> bool:
    """Apply the patch back onto the old image and compare with the new one.

    A patch split into several blocks is an in-place patch: it only applies
    correctly when ddelta_apply is given a staging *directory*, and the rebuilt
    image then lands in the old file itself. Applying such a patch to a plain
    output path silently returns success while producing wrong content, and
    vice versa, so the mode has to match the patch.

    Whether a patch is blocked is a property of the patch, not of the run: with
    a block size set, images smaller than one block still come out as ordinary
    single-block patches. ``flush_count`` (see :func:`parse_patch`) is the
    reliable signal, which is why *in_place* is derived per patch.

    The old image is copied first because ddelta_apply opens it read-write.
    """
    old_copy = os.path.join(work_dir, "verify.old")
    out_file = os.path.join(work_dir, "verify.out")
    stage_dir = os.path.join(work_dir, "verify.stage")
    shutil.copy2(old_file, old_copy)

    try:
        if in_place:
            os.makedirs(stage_dir, exist_ok=True)
            ok, _reason = run_apply(apply_tool, old_copy, stage_dir, patch_file)
            rebuilt = old_copy  # in-place: the old copy has become the new image
        else:
            ok, _reason = run_apply(apply_tool, old_copy, out_file, patch_file)
            rebuilt = out_file

        if not ok or not os.path.exists(rebuilt):
            return False
        return _same_content(rebuilt, new_file)
    finally:
        for path in (old_copy, out_file):
            if os.path.exists(path):
                os.remove(path)
        shutil.rmtree(stage_dir, ignore_errors=True)


def _print_progress(diff: FileDiff) -> None:
    """Per-file progress output, matching the original tool's wording."""
    print(f"\n  [分析] {diff.name}")
    print(f"    旧版: {format_size_full(diff.old_size)}")
    print(f"    新版: {format_size_full(diff.new_size)}")
    if diff.error:
        print(f"    [失败] {diff.error}")
        return
    if diff.patch_size:
        print(f"    [完成] 差分patch: {format_size_full(diff.patch_size)}")
        if diff.verified is True:
            print("    [校验] patch 回放成功，可还原新镜像")
        elif diff.verified is False:
            print("    [校验] patch 回放失败")
    else:
        print(
            f"    [比较] 变化字节: {format_size_full(diff.changed_bytes)} "
            f"({diff.change_ratio * 100:.1f}%)"
        )


def stage_patches(results: List[FileDiff], out_dir: str) -> None:
    """Copy generated patches out of the temporary directory into *out_dir*."""
    os.makedirs(out_dir, exist_ok=True)
    for r in results:
        if r.patch_file and os.path.exists(r.patch_file):
            dst = os.path.join(out_dir, f"{r.name}.patch")
            shutil.copy2(r.patch_file, dst)
            r.patch_file = dst


# ============ Reporting ============
#
# The report layout, wording and CSS are kept identical to the original
# ota_diff_analyzer.py so existing readers see the exact same document.


def format_size_full(size_bytes: int) -> str:
    """Format a byte count as ``1,234(1.2MB) 字节``."""
    mb = size_bytes / (1024 * 1024)
    if mb >= 1:
        return f"{size_bytes:,}({mb:.1f}MB) 字节"
    kb = size_bytes / 1024
    return f"{size_bytes:,}({kb:.1f}KB) 字节"


def format_size_mb(size_bytes: int) -> str:
    """Format a byte count as ``1.2MB`` / ``12.3KB``."""
    mb = size_bytes / (1024 * 1024)
    if mb >= 0.01:
        return f"{mb:.1f}MB"
    return f"{size_bytes / 1024:.1f}KB"


def _split_size(size_bytes: int) -> Tuple[str, str]:
    """Split ``format_size_full`` into the card value and its sub label."""
    text = format_size_full(size_bytes)
    head, _, rest = text.partition("(")
    return head, rest.split(")")[0]


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def change_reasons(diff: FileDiff) -> List[str]:
    """差异原因分析 — same wording as the original report."""
    out: List[str] = []
    if diff.zero_to_data:
        out.append(
            f"稀疏数据填充: {format_size_full(diff.zero_to_data)} 区域从零变为非零"
        )
    if diff.data_to_zero:
        out.append(f"数据清除: {format_size_full(diff.data_to_zero)} 区域变为零")
    if diff.content_change:
        out.append(
            f"内容修改: {format_size_full(diff.content_change)} 区域发生数据变化"
        )
    if diff.size_diff > 0:
        out.append(f"文件增大: {format_size_full(diff.size_diff)}")
    elif diff.size_diff < 0:
        out.append(f"文件缩小: {format_size_full(-diff.size_diff)}")
    if diff.region_count > 50:
        out.append(f"变化分散: 共 {diff.region_count} 个变化区域，变化较分散")
    elif diff.region_count:
        out.append(f"变化集中: 共 {diff.region_count} 个变化区域")

    info = diff.patch_info
    if info and info.fmt != "unknown" and diff.changed_bytes:
        if info.extra_size > info.diff_size:
            out.append(
                f"差分以字面数据为主: 额外数据 {format_size_full(info.extra_size)} "
                f"多于差分数据 {format_size_full(info.diff_size)}，"
                "说明新内容很少能从旧镜像推导出来"
            )
    if diff.patch_size and not diff.changed_bytes:
        out.append("两个包中该镜像逐字节相同，可直接从差分包中剔除")
    if diff.verified is False:
        out.append("该 patch 回放校验失败，不能用于升级")
    return out


def suggestions(analysis: Analysis) -> List[str]:
    """优化建议 — same wording as the original report, plus the compressed view."""
    out: List[str] = []
    results = analysis.results

    if analysis.zip_analysis:
        out.append(
            "📥 下载量应看压缩后的差分包: "
            f"{format_size_mb(analysis.zip_analysis.zip_size)}"
            f"（占新版本 {analysis.bundle_ratio * 100:.2f}%）。"
            f"未压缩的 {format_size_mb(analysis.total_patch_size)} 是 ddelta 的设计使然，不代表下载量"
        )

    unchanged = [r for r in results if r.patch_size and not r.changed_bytes]
    if unchanged:
        names = "、".join(r.name for r in unchanged[:5])
        out.append(f"♻️ {len(unchanged)} 个镜像逐字节相同（{names}），可从差分包中剔除")

    if [r for r in results if r.change_ratio > 0.5]:
        out.append(
            "⚠️ 高变化文件建议检查：是否可以优化编译选项减少随机变化，或者使用增量更新策略"
        )

    bloated = [r for r in results if r.compressed_size and r.compressed_ratio > 0.8]
    if bloated:
        out.append(
            "📦 大差分文件建议：对于变化过大的文件，考虑使用全量更新替代差分更新"
        )

    if [r for r in results if r.zero_to_data > 100000]:
        out.append(
            "💾 稀疏数据变化建议：检查固件是否正确处理了未使用区域，避免不必要的数据填充"
        )

    failed = [r for r in results if r.error]
    if failed:
        out.append(f"❌ {len(failed)} 个文件差分失败，请检查报告中的错误信息")

    unverified = [r for r in results if r.verified is False]
    if unverified:
        names = "、".join(r.name for r in unverified[:5])
        out.append(
            f"❌ {len(unverified)} 个 patch 回放校验失败（{names}），不可用于升级"
        )

    if analysis.only_in_new:
        out.append(f"➕ {len(analysis.only_in_new)} 个文件只存在于新版本，必须全量下发")

    if not out:
        out.append("✅ 当前差分结果正常，无需特别优化")
    return out


# ============ Markdown ============


def generate_markdown(analysis: Analysis, output_file: Optional[str] = None) -> str:
    """Render the analysis as a Markdown mirror of the HTML report."""
    lines: List[str] = []
    total_new = analysis.total_new_size

    lines.append("# OTA差分分析报告")
    lines.append("")
    lines.append(f"**分析时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**执行命令**: `{' '.join(sys.argv)}`")
    lines.append(f"**旧版本**: `{os.path.basename(analysis.old_package)}`")
    lines.append(f"**新版本**: `{os.path.basename(analysis.new_package)}`")
    if analysis.extensions:
        lines.append(f"**分析后缀**: {', '.join(sorted(analysis.extensions))}")
    lines.append("**分析方法**: ddelta_generate (bsdiff算法)")
    lines.append(f"**差分工具**: `{analysis.ddelta_tool or '不可用（仅字节比较）'}`")
    lines.append(f"**差分块大小 (blocksize)**: {analysis.blocksize_text}")
    lines.append("")

    lines.append("## 汇总信息")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|------|------|")
    lines.append(f"| 对比文件数 | {len(analysis.results):,} |")
    lines.append(f"| 差分块大小 (blocksize) | {analysis.blocksize_text} |")
    lines.append(f"| 旧版本总大小 | {format_size_full(analysis.total_old_size)} |")
    lines.append(f"| 新版本总大小 | {format_size_full(total_new)} |")
    lines.append(
        f"| 差分包总大小(未压缩) | {format_size_full(analysis.total_patch_size)} |"
    )
    lines.append(f"| 总体压缩率 | {analysis.total_patch_ratio * 100:.1f}% |")
    lines.append(f"| 变化字节数 | {format_size_full(analysis.total_changed_bytes)} |")
    if analysis.zip_analysis:
        za = analysis.zip_analysis
        lines.append(f"| **压缩后差分包** | **{format_size_full(za.zip_size)}** |")
        lines.append(f"| **压缩后占新版本** | **{analysis.bundle_ratio * 100:.2f}%** |")
        lines.append(f"| ZIP整体压缩率 | {za.compression_ratio * 100:.1f}% |")
    lines.append("")

    lines.append("## 各文件差分结果")
    lines.append("")
    lines.append(
        "| 文件名 | 旧版本 | 新版本 | 差分Patch | 压缩后 | 压缩后/新版本 | 变化字节 | 变化比例 | 变化等级 |"
    )
    lines.append(
        "|--------|--------|--------|-----------|--------|---------------|----------|----------|----------|"
    )
    for r in _ranked(analysis.results):
        raw = format_size_mb(r.patch_size) if r.patch_size else "n/a"
        deflated = format_size_mb(r.compressed_size) if r.compressed_size else "n/a"
        ratio = f"{r.compressed_ratio * 100:.2f}%" if r.compressed_size else "n/a"
        lines.append(
            f"| `{r.name}` | {format_size_mb(r.old_size)} | {format_size_mb(r.new_size)} | "
            f"{raw} | {deflated} | {ratio} | {format_size_mb(r.changed_bytes)} | "
            f"{r.change_ratio * 100:.1f}% | {_BADGE_TEXT[r.severity]} |"
        )
    lines.append("")

    structured = [
        r for r in analysis.results if r.patch_info and r.patch_info.fmt != "unknown"
    ]
    if structured:
        lines.append("## 差分Patch结构")
        lines.append("")
        lines.append(
            "| 文件名 | 格式 | 头部信息 | 控制块 | 差分数据 | 额外数据 | 控制项 | flush |"
        )
        lines.append(
            "|--------|------|----------|--------|----------|----------|--------|-------|"
        )
        for r in structured:
            info = r.patch_info
            assert info is not None
            lines.append(
                f"| `{r.name}` | {info.fmt} | {format_size_mb(info.header_size)} | "
                f"{format_size_mb(info.ctrl_size)} | {format_size_mb(info.diff_size)} | "
                f"{format_size_mb(info.extra_size)} | {info.entry_count:,} | {info.flush_count:,} |"
            )
        lines.append("")

    reasoned = [(r, change_reasons(r)) for r in _ranked(analysis.results)]
    reasoned = [(r, reasons) for r, reasons in reasoned if reasons]
    if reasoned:
        lines.append("## 差异原因分析")
        lines.append("")
        for r, reasons in reasoned:
            lines.append(f"### `{r.name}`")
            lines.append("")
            for reason in reasons:
                lines.append(f"- {reason}")
            lines.append("")

    if analysis.only_in_old or analysis.only_in_new:
        lines.append("## 未配对文件")
        lines.append("")
        for name in analysis.only_in_old:
            lines.append(f"- 新版本已删除: `{name}`")
        for name in analysis.only_in_new:
            lines.append(f"- 新版本新增: `{name}`")
        lines.append("")

    if analysis.zip_analysis:
        za = analysis.zip_analysis
        lines.append("## Diff文件压缩分析")
        lines.append("")
        lines.append(f"**压缩包路径**: `{za.zip_path}`")
        lines.append("")
        lines.append(
            "| 文件名 | new bin大小 | 原始大小(diff) | 压缩后大小 | 压缩率 | 占ZIP百分比 |"
        )
        lines.append(
            "|--------|-------------|----------------|------------|--------|-------------|"
        )
        zip_size = za.zip_size or 1
        for entry in za.entries:
            lines.append(
                f"| `{entry.name}` | {format_size_mb(entry.new_size)} | "
                f"{format_size_mb(entry.patch_size)} | {format_size_mb(entry.compressed_size)} | "
                f"{entry.compression_ratio * 100:.1f}% | "
                f"{entry.compressed_size / zip_size * 100:.1f}% |"
            )
        lines.append("")

    lines.append("## 优化建议")
    lines.append("")
    for item in suggestions(analysis):
        lines.append(f"- {item}")
    lines.append("")

    report = "\n".join(lines)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Markdown报告已保存到: {output_file}")
    return report


# ============ HTML ============
#
# CSS and section layout copied from the original ota_diff_analyzer.py.

_BADGE_TEXT = {"high": "高变化", "medium": "中变化", "low": "低变化"}
_BADGE_CLASS = {"high": "badge-high", "medium": "badge-medium", "low": "badge-low"}

_HTML_HEAD = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTA差分分析报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: white;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        .header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header .info {
            color: #666;
            font-size: 14px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .summary-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            text-align: center;
        }
        .summary-card .label {
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .summary-card .value {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        .summary-card .sub {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        .file-section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        .file-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        .file-name {
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }
        .file-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-high {
            background: #fee2e2;
            color: #dc2626;
        }
        .badge-medium {
            background: #fef3c7;
            color: #d97706;
        }
        .badge-low {
            background: #d1fae5;
            color: #059669;
        }
        .badge-info {
            background: #e0e7ff;
            color: #4338ca;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .metric {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .metric .metric-label {
            font-size: 11px;
            color: #666;
            margin-bottom: 5px;
        }
        .metric .metric-value {
            font-size: 16px;
            font-weight: bold;
            color: #333;
        }
        .metric .metric-sub {
            font-size: 10px;
            color: #888;
        }
        .reason-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 0 8px 8px 0;
            margin-top: 15px;
        }
        .reason-box h4 {
            color: #856404;
            margin-bottom: 10px;
        }
        .reason-box ul {
            margin-left: 20px;
            color: #666;
        }
        .reason-box li {
            margin-bottom: 5px;
        }
        .progress-bar {
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        .progress-fill.high {
            background: linear-gradient(90deg, #ff6b6b, #ee5a24);
        }
        .progress-fill.medium {
            background: linear-gradient(90deg, #feca57, #ff9ff3);
        }
        .progress-fill.low {
            background: linear-gradient(90deg, #48dbfb, #0abde3);
        }
        .comparison-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .comparison-table th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-size: 12px;
            color: #666;
            border-bottom: 2px solid #dee2e6;
        }
        .comparison-table td {
            padding: 12px;
            border-bottom: 1px solid #f0f0f0;
        }
        .negative {
            color: #dc2626;
        }
        .positive {
            color: #059669;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: white;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">"""


def _ranked(results: List[FileDiff]) -> List[FileDiff]:
    """Order files by download impact, falling back to raw change size."""
    return sorted(
        results,
        key=lambda r: (r.compressed_size or r.patch_size or r.changed_bytes),
        reverse=True,
    )


def _summary_cards(analysis: Analysis) -> str:
    cards = []
    for label, size, sub in [
        ("旧版本总大小", analysis.total_old_size, None),
        ("新版本总大小", analysis.total_new_size, None),
        ("差分包总大小", analysis.total_patch_size, None),
    ]:
        value, unit = _split_size(size)
        cards.append((label, value, sub or unit))

    cards.append(
        ("总体压缩率", f"{analysis.total_patch_ratio * 100:.1f}%", "差分/新版本")
    )
    if not analysis.ddelta_tool:
        card = ("差分块大小", "n/a", "未生成 patch")
    elif analysis.blocksize:
        card = ("差分块大小", format_size_mb(analysis.blocksize), "blocksize")
    else:
        card = ("差分块大小", "未传", "非原地打补丁")
    cards.append(card)

    if analysis.zip_analysis:
        value, unit = _split_size(analysis.zip_analysis.zip_size)
        cards.append(("压缩后差分包", value, unit))
        cards.append(
            ("压缩后/新版本", f"{analysis.bundle_ratio * 100:.2f}%", "实际下载占比")
        )

    parts = ['        <div class="summary-grid">']
    for label, value, sub in cards:
        parts.append(
            f'            <div class="summary-card">\n'
            f'                <div class="label">{label}</div>\n'
            f'                <div class="value">{value}</div>\n'
            f'                <div class="sub">{sub}</div>\n'
            f"            </div>"
        )
    parts.append("        </div>")
    return "\n".join(parts)


def _metric(label: str, value: str, sub: str) -> str:
    return (
        f'                <div class="metric">\n'
        f'                    <div class="metric-label">{label}</div>\n'
        f'                    <div class="metric-value">{value}</div>\n'
        f'                    <div class="metric-sub">{sub}</div>\n'
        f"                </div>"
    )


def _patch_structure_table(diff: FileDiff) -> str:
    info = diff.patch_info
    if not info or info.fmt == "unknown":
        return ""
    total = info.total_size or 1
    rows = [
        ("头部信息", info.header_size),
        ("控制块", info.ctrl_size),
        ("差分数据（源自旧镜像）", info.diff_size),
        ("额外数据（新增字面数据）", info.extra_size),
    ]
    parts = [
        '            <table class="comparison-table">',
        "                <tr>",
        f"                    <th>差分Patch结构（{info.fmt}）</th>",
        "                    <th>大小</th>",
        "                    <th>占比</th>",
        "                </tr>",
    ]
    for label, size in rows:
        parts.append(
            f"                <tr>\n"
            f"                    <td>{label}</td>\n"
            f"                    <td>{format_size_full(size)}</td>\n"
            f"                    <td>{size / total * 100:.1f}%</td>\n"
            f"                </tr>"
        )
    parts.append(
        f"                <tr>\n"
        f"                    <td>控制项 / flush 记录</td>\n"
        f"                    <td>{info.entry_count:,} 条</td>\n"
        f"                    <td>{info.flush_count:,} 条</td>\n"
        f"                </tr>"
    )
    parts.append("            </table>")
    if info.truncated:
        parts.append(
            '            <div class="reason-box">patch 数据流提前结束，以上数据不完整</div>'
        )
    return "\n".join(parts)


def _file_sections(analysis: Analysis) -> str:
    parts: List[str] = []
    for r in _ranked(analysis.results):
        badge_class = _BADGE_CLASS[r.severity]
        badge_text = _BADGE_TEXT[r.severity]

        extra_badge = ""
        if r.error:
            extra_badge = '<span class="file-badge badge-high">差分失败</span>'
        elif r.verified is True:
            extra_badge = '<span class="file-badge badge-low">校验通过</span>'
        elif r.verified is False:
            extra_badge = '<span class="file-badge badge-high">校验失败</span>'

        metrics = []
        for label, size in [
            ("旧版本大小", r.old_size),
            ("新版本大小", r.new_size),
            ("差分Patch大小", r.patch_size),
            ("变化字节数", r.changed_bytes),
        ]:
            value, unit = _split_size(size)
            metrics.append(_metric(label, value, unit))
        metrics.append(
            _metric("变化比例", f"{r.change_ratio * 100:.1f}%", "差异/总大小")
        )
        metrics.append(
            _metric(
                "压缩率",
                f"{r.patch_ratio * 100:.1f}%" if r.patch_size else "n/a",
                "patch/新版本",
            )
        )
        if r.compressed_size:
            value, unit = _split_size(r.compressed_size)
            metrics.append(_metric("压缩后Patch", value, unit))
            metrics.append(
                _metric(
                    "压缩后/新版本", f"{r.compressed_ratio * 100:.2f}%", "实际下载占比"
                )
            )

        reasons = change_reasons(r)
        reasons_html = ""
        if reasons:
            items = "".join(f"<li>{_esc(reason)}</li>" for reason in reasons)
            reasons_html = (
                '            <div class="reason-box">\n'
                "                <h4>📊 差异原因分析</h4>\n"
                f"                <ul>{items}</ul>\n"
                "            </div>"
            )

        error_html = ""
        if r.error:
            error_html = (
                '            <div class="reason-box">\n'
                "                <h4>❌ 差分失败</h4>\n"
                f"                <ul><li>{_esc(r.error)}</li></ul>\n"
                "            </div>"
            )

        parts.append(
            f'        <div class="file-section">\n'
            f'            <div class="file-header">\n'
            f'                <span class="file-name">📄 {_esc(r.name)}</span>\n'
            f'                <span><span class="file-badge {badge_class}">{badge_text}</span>'
            f"{extra_badge}</span>\n"
            f"            </div>\n"
            f'            <div class="metrics-grid">\n' + "\n".join(metrics) + "\n"
            f"            </div>\n"
            f'            <div class="progress-bar">\n'
            f'                <div class="progress-fill {r.severity}" '
            f'style="width: {min(r.change_ratio * 100, 100):.1f}%"></div>\n'
            f"            </div>\n"
            f"{_patch_structure_table(r)}\n"
            f"{error_html}\n"
            f"{reasons_html}\n"
            f"        </div>"
        )
    return "\n".join(parts)


def _unpaired_section(analysis: Analysis) -> str:
    if not (analysis.only_in_old or analysis.only_in_new):
        return ""
    rows = []
    for name in analysis.only_in_old:
        rows.append(
            f"                <tr><td>{_esc(name)}</td><td>新版本已删除</td></tr>"
        )
    for name in analysis.only_in_new:
        rows.append(
            f"                <tr><td>{_esc(name)}</td><td>新版本新增，必须全量下发</td></tr>"
        )
    return (
        '        <div class="file-section">\n'
        '            <div class="file-header">\n'
        '                <span class="file-name">🔀 未配对文件</span>\n'
        f'                <span class="file-badge badge-info">{len(rows)} 个</span>\n'
        "            </div>\n"
        '            <table class="comparison-table">\n'
        "                <tr><th>文件名</th><th>状态</th></tr>\n"
        + "\n".join(rows)
        + "\n"
        "            </table>\n"
        "        </div>"
    )


def _bundle_section(analysis: Analysis) -> str:
    za = analysis.zip_analysis
    if not za:
        return ""
    zip_size = za.zip_size or 1
    rows = []
    for entry in za.entries:
        rows.append(
            f"                <tr>\n"
            f"                    <td>{_esc(entry.name)}</td>\n"
            f"                    <td>{format_size_mb(entry.new_size)}</td>\n"
            f"                    <td>{format_size_mb(entry.patch_size)}</td>\n"
            f"                    <td>{format_size_mb(entry.compressed_size)}</td>\n"
            f"                    <td>{entry.compression_ratio * 100:.1f}%</td>\n"
            f"                    <td>{entry.compressed_size / zip_size * 100:.1f}%</td>\n"
            f"                </tr>"
        )

    metrics = [
        _metric("Diff文件数量", f"{za.file_count}", "个"),
        _metric("原始总大小", format_size_mb(za.total_original_size), "未压缩diff"),
        _metric("压缩后总大小", format_size_mb(za.zip_size), "ZIP压缩"),
        _metric("整体压缩率", f"{za.compression_ratio * 100:.1f}%", "节省空间"),
        _metric(
            "节省空间",
            format_size_mb(za.total_original_size - za.zip_size),
            "压缩收益",
        ),
    ]

    advice = (
        "<li>💡 建议: 压缩率较低，可考虑使用更高压缩比的算法如7z或xz</li>"
        if za.compression_ratio * 100 < 30
        else "<li>✅ 压缩效果良好</li>"
    )

    return (
        '        <div class="file-section">\n'
        '            <div class="file-header">\n'
        '                <span class="file-name">📦 Diff文件压缩分析</span>\n'
        '                <span class="file-badge badge-medium">ZIP压缩</span>\n'
        "            </div>\n"
        '            <div class="metrics-grid">\n' + "\n".join(metrics) + "\n"
        "            </div>\n"
        '            <h4 style="margin: 20px 0 15px; color: #333;">📋 各Diff文件压缩详情</h4>\n'
        '            <table class="comparison-table">\n'
        "                <tr>\n"
        "                    <th>文件名</th>\n"
        "                    <th>new bin大小</th>\n"
        "                    <th>原始大小(diff)</th>\n"
        "                    <th>压缩后大小</th>\n"
        "                    <th>压缩率</th>\n"
        "                    <th>占ZIP百分比</th>\n"
        "                </tr>\n" + "\n".join(rows) + "\n"
        "            </table>\n"
        '            <div class="reason-box" style="background: #d1ecf1; '
        'border-left-color: #0c5460; margin-top: 15px;">\n'
        '                <h4 style="color: #0c5460;">📊 压缩效果分析</h4>\n'
        "                <ul>\n"
        f"                    <li>Diff文件压缩包路径: {_esc(os.path.basename(za.zip_path))}</li>\n"
        f"                    <li>ZIP压缩包大小: {format_size_mb(za.zip_size)}</li>\n"
        f"                    <li>整体压缩率: {za.compression_ratio * 100:.1f}% "
        f"(原始 {format_size_mb(za.total_original_size)} → "
        f"压缩后 {format_size_mb(za.zip_size)})</li>\n"
        f"                    {advice}\n"
        "                </ul>\n"
        "            </div>\n"
        "        </div>"
    )


def generate_html(analysis: Analysis, output_file: Optional[str] = None) -> str:
    """Render the analysis as the same HTML report the original tool produced."""
    tool_note = ""
    if not analysis.ddelta_tool:
        tool_note = (
            '        <div class="file-section">\n'
            '            <div class="reason-box">\n'
            "                <h4>⚠️ 未找到 ddelta_generate</h4>\n"
            "                <ul><li>本次未生成差分patch，以下数据仅来自字节级比较，"
            "不能代表真实差分包大小</li></ul>\n"
            "            </div>\n"
            "        </div>"
        )

    suggestions_html = "".join(
        f"<li>{_esc(item)}</li>" for item in suggestions(analysis)
    )

    html = f"""{_HTML_HEAD}
        <div class="header">
            <h1>🔍 OTA差分分析报告</h1>
            <div class="info">
                <p>分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>旧版本: {_esc(os.path.basename(analysis.old_package))}</p>
                <p>新版本: {_esc(os.path.basename(analysis.new_package))}</p>
                <p>分析方法: ddelta_generate (bsdiff算法)</p>
                <p>差分工具: {_esc(analysis.ddelta_tool or '不可用（仅字节比较）')}</p>
                <p><b>差分块大小 (blocksize): {analysis.blocksize_text}</b></p>
            </div>
        </div>

{tool_note}
{_summary_cards(analysis)}
{_file_sections(analysis)}
{_unpaired_section(analysis)}
        <div class="file-section">
            <div class="file-header">
                <span class="file-name">💡 优化建议</span>
            </div>
            <div class="reason-box" style="background: #d1ecf1; border-left-color: #0c5460;">
                <h4 style="color: #0c5460;">基于分析结果的建议</h4>
                <ul>
                    {suggestions_html}
                </ul>
            </div>
        </div>

{_bundle_section(analysis)}

        <div class="footer">
            <p>报告生成工具: miwear_ota {__version__} | 差分算法: ddelta_generate (bsdiff)</p>
        </div>
    </div>
</body>
</html>
"""

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"HTML报告已保存到: {output_file}")
    return html


def print_summary(analysis: Analysis) -> None:
    """Print the terminal summary in the original tool's layout."""
    print()
    print("=" * 60)
    print("✅ 分析完成!")
    print("=" * 60)
    print()
    print("📊 汇总信息:")
    print(f"  对比文件数量: {len(analysis.results)}")
    print(f"  差分块大小(blocksize): {analysis.blocksize_text}")
    print(f"  旧版本总大小: {format_size_mb(analysis.total_old_size)}")
    print(f"  新版本总大小: {format_size_mb(analysis.total_new_size)}")
    print(f"  差分包总大小(未压缩): {format_size_mb(analysis.total_patch_size)}")
    print(f"  总体压缩率: {analysis.total_patch_ratio * 100:.1f}%")
    print(f"  变化字节数: {format_size_mb(analysis.total_changed_bytes)}")

    za = analysis.zip_analysis
    if za:
        print()
        print("📦 Diff文件压缩信息:")
        print(f"  压缩包路径: {za.zip_path}")
        print(f"  压缩包大小: {format_size_mb(za.zip_size)}")
        print(f"  原始总大小: {format_size_mb(za.total_original_size)}")
        print(f"  整体压缩率: {za.compression_ratio * 100:.1f}%")
        print(f"  节省空间: {format_size_mb(za.total_original_size - za.zip_size)}")
        print(f"  压缩后占新版本: {analysis.bundle_ratio * 100:.2f}%")

        print()
        print("  各文件详情(按占ZIP百分比排序):")
        header = (
            f"  {'文件名':<30} {'new bin':>10} {'原始大小':>10} "
            f"{'压缩后':>10} {'压缩率':>8} {'占ZIP':>8}"
        )
        print(header)
        print(f"  {'-' * 30} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 8} {'-' * 8}")
        zip_size = za.zip_size or 1
        for entry in za.entries:
            print(
                f"  {entry.name:<30} {format_size_mb(entry.new_size):>10} "
                f"{format_size_mb(entry.patch_size):>10} "
                f"{format_size_mb(entry.compressed_size):>10} "
                f"{entry.compression_ratio * 100:.1f}%{'':<2} "
                f"{entry.compressed_size / zip_size * 100:.1f}%"
            )
    else:
        print()
        print("  各文件详情:")
        for r in _ranked(analysis.results):
            print(
                f"  {r.name:<30} {format_size_mb(r.new_size):>10} "
                f"变化 {format_size_mb(r.changed_bytes):>10} "
                f"({r.change_ratio * 100:.1f}%)"
            )
    print()


def open_in_browser(path: str) -> None:
    """Open a generated report in the default browser."""
    webbrowser.open(f"file://{os.path.abspath(path)}")


# ============ CLI ============

DEFAULT_EXTENSIONS = ["bin"]

# Only these are stripped when deriving a report name, so a package whose name
# carries a dotted version keeps it instead of being cut at the first dot.
ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tar.xz",
    ".tar.bz2",
    ".tgz",
    ".txz",
    ".tar",
    ".zip",
)


def package_stem(path: str) -> str:
    """Derive a report friendly name from a package path."""
    name = os.path.basename(os.path.abspath(path.rstrip(os.sep)))
    lower = name.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            return name[: -len(suffix)]
    return name


def parse_extensions(values: Optional[list]) -> Set[str]:
    """Normalize ``-e`` values into a lowercase extension set.

    ``-e all`` (or ``-e ''``) disables filtering so every file gets diffed.
    """
    if not values:
        return set(DEFAULT_EXTENSIONS)
    out: Set[str] = set()
    for value in values:
        for item in value.replace(",", " ").split():
            item = item.strip().lstrip("*").lstrip(".").lower()
            if item in ("all", "*"):
                return set()
            if item:
                out.add(item)
    return out


def parse_blocksize(value: str) -> int:
    """Parse a ``--blocksize`` value such as ``0``, ``4096``, ``8M`` or ``32MB``.

    This must match the block size your OTA packaging step passes to
    ``ddelta_generate``: a non-zero block size switches ddelta to in-place
    patching, which changes the resulting patch, and the value is project
    specific. ``0`` means the block size argument is not passed at all.
    """
    text = value.strip().upper().replace("IB", "").rstrip("B")
    if not text:
        raise argparse.ArgumentTypeError("blocksize must not be empty")

    units = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}
    factor = 1
    if text[-1] in units:
        factor = units[text[-1]]
        text = text[:-1]

    try:
        number = int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid blocksize: {value!r} (try 0, 4096, 8M, 32M)"
        )
    if number < 0:
        raise argparse.ArgumentTypeError("blocksize must not be negative")
    return number * factor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miwear_ota",
        description="Analyze the binary delta between two OTA packages using ddelta (bsdiff family)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "ddelta_generate is not bundled with this package. Build it once from the\n"
            "Vela source tree and it will be picked up automatically:\n"
            "    cd <vela-root>/external/ddelta/ddelta && make clean && make\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    parser.add_argument(
        "old", help="old OTA package (.zip / .tar.gz) or an already extracted directory"
    )
    parser.add_argument(
        "new", help="new OTA package (.zip / .tar.gz) or an already extracted directory"
    )

    parser.add_argument(
        "-e",
        "--ext",
        action="extend",
        nargs="+",
        metavar="EXT",
        help="payload extensions to diff (e.g. -e bin, -e bin img, -e bin,img, -e all). Default: bin",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="HTML report path (default: ota_diff_report-<old>-<new>.html)",
    )
    parser.add_argument(
        "--no-output",
        action="store_true",
        help="print the summary only, write no report files",
    )
    parser.add_argument(
        "--no-markdown", action="store_true", help="skip the Markdown report"
    )
    parser.add_argument(
        "--open-browser", action="store_true", help="open the HTML report when done"
    )

    parser.add_argument(
        "--ddelta",
        metavar="PATH",
        help=f"path to ddelta_generate (env: {ENV_GENERATE})",
    )
    parser.add_argument(
        "--ddelta-apply",
        metavar="PATH",
        help=f"path to ddelta_apply, used by --verify (env: {ENV_APPLY})",
    )
    parser.add_argument(
        "--no-ddelta",
        action="store_true",
        help="skip patch generation and report byte level comparison only",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="apply every patch back onto the old file and confirm it reproduces the new file",
    )
    parser.add_argument(
        "--blocksize",
        type=parse_blocksize,
        default=None,
        metavar="SIZE",
        help="REQUIRED: ddelta block size, e.g. 0, 8M, 16M, 32M. Must match the block size "
        "your OTA packaging step passes to ddelta_generate (project specific). 0 means the "
        "argument is not passed, i.e. a non in-place patch. Not needed with --no-ddelta",
    )
    parser.add_argument(
        "--keep-patches",
        metavar="DIR",
        help="directory to keep the generated .patch files in (default: alongside the report)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="suppress per-file progress output"
    )
    return parser


def resolve_tools(args: argparse.Namespace) -> tuple:
    """Locate the ddelta binaries and explain what to do when missing."""
    if args.no_ddelta:
        return None, None

    generate = find_generate(args.ddelta)
    if not generate:
        if args.ddelta:
            print(f"[错误] 不是可执行文件: {args.ddelta}", file=sys.stderr)
            sys.exit(1)
        print(
            "Warning: ddelta_generate not found, falling back to byte level comparison.",
            file=sys.stderr,
        )
        print(BUILD_HINT, file=sys.stderr)
        print(file=sys.stderr)
        return None, None

    apply_tool = None
    if args.verify:
        apply_tool = find_apply(args.ddelta_apply, sibling_of=generate)
        if not apply_tool:
            print(
                "[错误] --verify 需要 ddelta_apply，但未找到",
                file=sys.stderr,
            )
            print(
                BUILD_HINT.replace(ENV_GENERATE, ENV_APPLY),
                file=sys.stderr,
            )
            sys.exit(1)

    return generate, apply_tool


BLOCKSIZE_HINT = """[错误] 必须显式指定 --blocksize
  它决定 ddelta 是否使用原地打补丁，直接影响生成的差分包，且每个项目取值不同。
  常用取值:
    --blocksize 0      不给 ddelta_generate 传块大小（非原地打补丁）
    --blocksize 8M
    --blocksize 16M
    --blocksize 32M
  取值必须与打 OTA 包时传给 ddelta_generate 的块大小保持一致，
  否则报告里的差分包大小不等于真实 OTA 包的大小。
  只做字节比较、不生成 patch 时可加 --no-ddelta，此时无需 --blocksize。"""


def main() -> None:
    args = build_parser().parse_args()

    for path in (args.old, args.new):
        if not os.path.exists(path):
            print(f"[错误] 文件或目录不存在: {path}", file=sys.stderr)
            sys.exit(1)

    if args.blocksize is None and not args.no_ddelta:
        print(BLOCKSIZE_HINT, file=sys.stderr)
        sys.exit(1)
    blocksize = args.blocksize or 0

    extensions = parse_extensions(args.ext)
    generate_tool, apply_tool = resolve_tools(args)
    blocksize_text = (
        f"{format_size_mb(blocksize)} ({blocksize:,} 字节)"
        if blocksize
        else "0（未传块大小，非原地打补丁）"
    )

    tag = f"{package_stem(args.old)}-{package_stem(args.new)}"

    html_path = args.output or f"ota_diff_report-{tag}.html"
    report_dir = os.path.dirname(os.path.abspath(html_path))
    md_path = os.path.splitext(html_path)[0] + ".md"

    print("=" * 72)
    print("🔍 OTA差分分析工具")
    print("=" * 72)
    print(f"  旧版本: {args.old}")
    print(f"  新版本: {args.new}")
    print(f"  分析后缀: {', '.join(sorted(extensions)) if extensions else '全部文件'}")
    print(f"  差分工具: {generate_tool or '不可用（仅字节比较）'}")
    print(f"  差分块大小: {blocksize_text}")
    print("=" * 72)

    with tempfile.TemporaryDirectory(prefix="miwear_ota_") as work_dir:
        analysis = analyze(
            old_package=args.old,
            new_package=args.new,
            work_dir=work_dir,
            patch_dir=os.path.join(work_dir, "patch"),
            extensions=extensions,
            ddelta_tool=generate_tool,
            apply_tool=apply_tool,
            blocksize=blocksize,
            verbose=not args.quiet,
        )

        if not analysis.results:
            print("[错误] 未找到可配对的文件，无法比较", file=sys.stderr)
            sys.exit(1)

        has_patches = any(r.patch_file for r in analysis.results)
        if has_patches and not args.no_output:
            print("\n[步骤4] 创建Diff文件压缩包...")
            patch_out = args.keep_patches or os.path.join(
                report_dir, f"ota_diff_patches-{tag}"
            )
            stage_patches(analysis.results, patch_out)
            analysis.zip_analysis = bundle_patches(
                analysis.results, os.path.join(report_dir, f"ota_diff-{tag}.zip")
            )
            print(f"  [完成] patch 目录: {patch_out}")
            print(f"  [完成] Diff压缩包: {analysis.zip_analysis.zip_path}")

        print_summary(analysis)

        if args.no_output:
            return

        if not args.no_markdown:
            generate_markdown(analysis, md_path)
        generate_html(analysis, html_path)

        if args.open_browser:
            open_in_browser(html_path)


if __name__ == "__main__":
    main()
