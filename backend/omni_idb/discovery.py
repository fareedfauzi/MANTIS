"""Content-based sample discovery and validation."""

from __future__ import annotations

import enum
import hashlib
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

MAX_PROBE = 1024 * 1024


def compute_file_md5(path: Path) -> str:
    """Fast MD5 checksum computation for a sample."""
    try:
        if path.stat().st_size > 200 * 1024 * 1024:
            return "--"
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(262144), b""):
                h.update(chunk)
        return h.hexdigest().lower()
    except Exception:
        return ""


class SampleKind(enum.Enum):
    EXECUTABLE = ("Executable", "executable")
    DOTNET_ASSEMBLY = (".NET assembly", "dotnet_assembly")
    IDA_DATABASE = ("IDA database", "ida_database")
    GHIDRA_PROJECT = ("Ghidra project", "ghidra_project")

    @property
    def label(self) -> str:
        return self.value[0]

    @property
    def job_value(self) -> str:
        return self.value[1]


@dataclass
class Sample:
    path: Path
    size: int
    kind: SampleKind
    status: str = "Ready"
    stage: str = "-"
    md5: str = ""
    start_time: Optional[float] = None
    elapsed_seconds: Optional[float] = None
    added_time: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))


    def is_pending(self) -> bool:
        return self.status in ("Ready", "Queued", "Pending", "")

    def is_running(self) -> bool:
        return self.status in ("Opening in IDA", "Running in IDA") or self.status.startswith(
            ("Renaming", "Analyzing", "Processing", "Running")
        )

    def is_complete(self) -> bool:
        return self.status == "Complete"

    def is_failed(self) -> bool:
        return self.status == "Failed"

    def is_stopped(self) -> bool:
        return self.status.startswith("Stopped")

    def is_skipped(self) -> bool:
        return self.status.startswith("Skipped")

    def time_spent(self) -> str:
        if self.elapsed_seconds is not None:
            secs = max(0, int(self.elapsed_seconds))
            mins = secs // 60
            rem = secs % 60
            if mins > 0:
                return f"{mins}m {rem:02d}s"
            return f"{rem}s"
        if self.start_time is not None and self.is_running():
            secs = max(0, int(time.time() - self.start_time))
            mins = secs // 60
            rem = secs % 60
            return f"{mins:02d}:{rem:02d}"
        return "--"


@dataclass
class RejectedFile:
    path: Path
    reason: str


@dataclass
class DiscoveryReport:
    samples: list[Sample] = field(default_factory=list)
    rejected: list[RejectedFile] = field(default_factory=list)


class ClassifyError(Exception):
    """Raised with a human-readable rejection reason."""


_NON_SAMPLE_SIGNATURES = [
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP/archive or Office document"),
    (b"PK\x05\x06", "ZIP archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/Office document"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"RIFF", "RIFF media file"),
]


def _known_non_sample(data: bytes) -> Optional[str]:
    for signature, label in _NON_SAMPLE_SIGNATURES:
        if data.startswith(signature):
            return label
    return None


def _valid_pe(data: bytes, file_size: int) -> bool:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return False
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset < 0x40 or offset + 24 > len(data):
        return False
    if data[offset : offset + 4] != b"PE\0\0":
        return False
    machine, sections = struct.unpack_from("<HH", data, offset + 4)
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    if (
        machine not in (0x014C, 0x01C0, 0x01C2, 0x01C4, 0x0200, 0x8664, 0xAA64)
        or sections == 0
        or sections > 96
        or optional_size < 2
    ):
        return False
    optional = offset + 24
    end = optional + optional_size
    if end > len(data) or end > file_size:
        return False
    return struct.unpack_from("<H", data, optional)[0] in (0x010B, 0x020B)


def _rva_to_offset(data: bytes, pe_offset: int, rva: int, size: int = 1) -> Optional[int]:
    """Map an RVA through the PE section table and require the bytes to be file-backed."""
    sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    for index in range(sections):
        entry = section_table + index * 40
        if entry + 40 > len(data):
            return None
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, entry + 8)
        if virtual_address <= rva and rva + size <= virtual_address + raw_size:
            offset = raw_offset + (rva - virtual_address)
            return offset
    return None


def _is_dotnet_pe(data: bytes, path: Optional[Path] = None) -> bool:
    """Validate the CLR directory, CLI header, and metadata signature of a .NET PE."""
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return False
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset < 0x40 or offset + 24 > len(data):
        return False
    if data[offset : offset + 4] != b"PE\0\0":
        return False
    optional = offset + 24
    if optional + 2 > len(data):
        return False
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x010B:
        data_dir = optional + 96
    elif magic == 0x020B:
        data_dir = optional + 112
    else:
        return False
    # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR is directory index 14 (8 bytes per entry)
    com_dir = data_dir + 14 * 8
    if com_dir + 8 > len(data):
        return False
    va, size = struct.unpack_from("<II", data, com_dir)
    if va == 0 or size < 0x48:
        return False
    def read_at(file_offset: int, length: int) -> bytes:
        if file_offset + length <= len(data):
            return data[file_offset : file_offset + length]
        if path is None:
            return b""
        try:
            with open(path, "rb") as handle:
                handle.seek(file_offset)
                return handle.read(length)
        except OSError:
            return b""

    cli_offset = _rva_to_offset(data, offset, va, 0x10)
    if cli_offset is None:
        return False
    cli_header = read_at(cli_offset, 0x10)
    if len(cli_header) != 0x10:
        return False
    header_size, _major, _minor, metadata_rva, metadata_size = struct.unpack_from("<IHHII", cli_header)
    if header_size < 0x48 or metadata_rva == 0 or metadata_size < 16:
        return False
    metadata_offset = _rva_to_offset(data, offset, metadata_rva, 4)
    return metadata_offset is not None and read_at(metadata_offset, 4) == b"BSJB"


def _valid_elf(data: bytes) -> bool:
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        return False
    cls, endian = data[4], data[5]
    if cls not in (1, 2) or endian not in (1, 2) or data[6] != 1:
        return False
    fmt = "<H" if endian == 1 else ">H"
    file_type = struct.unpack_from(fmt, data, 16)[0]
    machine = struct.unpack_from(fmt, data, 18)[0]
    return 1 <= file_type <= 4 and machine != 0 and (cls == 1 or len(data) >= 64)


_MACHO_MAGICS = {
    bytes.fromhex(h)
    for h in (
        "feedface",
        "cefaedfe",
        "feedfacf",
        "cffaedfe",
        "cafebabe",
        "bebafeca",
        "cafebabf",
        "bfbafeca",
    )
}


def _valid_macho(data: bytes) -> bool:
    if len(data) < 28 or data[:4] not in _MACHO_MAGICS:
        return False
    # If fat binary magic (cafebabe/bebafeca), verify it's not a Java .class file.
    # Java class files also start with cafebabe, followed by minor_version (u16) and major_version (u16 >= 45).
    # Mach-O fat headers have nfat_arch (1..32) and cputype at offset 8.
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        endian = "big" if data[:4] == b"\xca\xfe\xba\xbe" else "little"
        nfat = int.from_bytes(data[4:8], endian)
        if not (1 <= nfat <= 32):
            return False
        cputype = int.from_bytes(data[8:12], endian)
        base_cpu = cputype & 0x00FFFFFF
        # Mach-O CPU types: VAX=1, MC680x0=6, I386=7, MIPS=8, HPPA=11, ARM=12, POWERPC=18
        if base_cpu not in (1, 6, 7, 8, 11, 12, 18):
            return False
    return True


def _looks_like_text(data: bytes) -> bool:
    sample = data[: 64 * 1024]
    if not sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 0x20 <= b <= 0x7E)
    return printable * 100 >= len(sample) * 90


def classify_sample(path: Path | str) -> SampleKind:
    """Return the sample kind, or raise ``ClassifyError`` with the rejection reason."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ClassifyError(f"cannot read metadata: {error}") from error
    if size == 0:
        raise ClassifyError("empty file")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_PROBE)
    except OSError as error:
        raise ClassifyError(f"cannot open file: {error}") from error

    label = _known_non_sample(data)
    if label:
        raise ClassifyError(f"{label} is not an executable sample")
    if _valid_pe(data, size):
        if _is_dotnet_pe(data, path):
            return SampleKind.DOTNET_ASSEMBLY
        return SampleKind.EXECUTABLE
    if _valid_elf(data) or _valid_macho(data):
        return SampleKind.EXECUTABLE

    ext = path.suffix.lstrip(".").lower()
    if ext in ("py", "pyw", "pyc", "pyo", "pyd"):
        raise ClassifyError("Python script is not a compiled executable or IDA database")
    if ext in ("bat", "cmd", "ps1", "sh", "bash", "zsh"):
        raise ClassifyError("Shell/batch script is not a compiled executable or IDA database")
    if ext in ("txt", "md", "json", "yml", "yaml", "xml", "csv", "tsv", "log", "ini", "cfg", "toml"):
        raise ClassifyError("Text/data file is not a compiled executable or IDA database")
    if ext in ("idb", "i64"):
        if size < 32 or not data.startswith((b"IDA0", b"IDA1", b"IDA2")):
            raise ClassifyError("malformed IDA database (invalid IDB signature)")
        return SampleKind.IDA_DATABASE
    if ext in ("gzf", "gpr"):
        if ext == "gpr":
            rep_dir = path.parent / f"{path.stem}.rep"
            if not rep_dir.is_dir():
                raise ClassifyError(f"Ghidra project directory missing: '{rep_dir.name}' is required next to '{path.name}'")
        return SampleKind.GHIDRA_PROJECT
    if ext in ("exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "exe_"):
        raise ClassifyError("malformed PE file (missing or invalid PE headers)")
    if ext in ("elf", "so"):
        raise ClassifyError("malformed ELF file")
    if ext in ("macho", "dylib"):
        raise ClassifyError("malformed Mach-O file")
    if ext in ("bin", "raw", "sc", "shellcode"):
        raise ClassifyError("Raw shellcode binary must first be loaded and converted to code/functions in an IDA database (.idb/.i64)")
    raise ClassifyError("unrecognized or unsupported file format")


def _push_classified(path: Path, report: DiscoveryReport) -> None:
    try:
        kind = classify_sample(path)
    except ClassifyError as error:
        report.rejected.append(RejectedFile(path, str(error)))
        return
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    sample_md5 = compute_file_md5(path) if kind != SampleKind.IDA_DATABASE else ""
    report.samples.append(Sample(path, size, kind, md5=sample_md5))



SKIP_DISCOVERY_EXTENSIONS = {
    ".py", ".pyw", ".pyc", ".pyo",
    ".bat", ".cmd", ".ps1", ".sh", ".bash", ".zsh",
    ".txt", ".md", ".json", ".yml", ".yaml", ".xml", ".csv", ".tsv", ".log", ".ini", ".cfg", ".toml",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar",
}


def discover(
    input_path: Path | str,
    recursive: bool = True,
    output_root: Path | str | None = None,
) -> DiscoveryReport:
    input_path = Path(input_path)
    report = DiscoveryReport()
    if input_path.is_file():
        _push_classified(input_path, report)
        return report
    if not input_path.is_dir():
        raise OSError(f"Input path is not a file or directory: {input_path}")

    output = None
    if output_root and str(output_root).strip():
        try:
            output = Path(output_root).resolve()
        except OSError:
            output = None

    seen: set[Path] = set()
    skip_names = {".git", "target", "__pycache__", ".vscode", ".idea", "node_modules", "venv", ".venv"}
    for current, dirs, files in os.walk(input_path):
        current_path = Path(current)
        kept = []
        for name in dirs:
            child = current_path / name
            if name.lower() in skip_names:
                continue
            if output is not None:
                try:
                    if child.resolve() == output:
                        continue
                except OSError:
                    pass
            kept.append(name)
        dirs[:] = kept if recursive else []
        for name in files:
            path = current_path / name
            if path.suffix.lower() in SKIP_DISCOVERY_EXTENSIONS:
                continue
            try:
                canonical = path.resolve()
            except OSError:
                canonical = path
            if canonical in seen:
                continue
            seen.add(canonical)
            _push_classified(path, report)

    report.samples.sort(key=lambda s: s.path)
    report.rejected.sort(key=lambda r: r.path)
    return report


def format_size(size: float) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"
