"""Pure-Python build and compatibility metadata."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Tuple

PLUGIN_ID = "genesect"
PLUGIN_DISPLAY_NAME = "Genesect"
PLUGIN_ENTRY_FILE = "Genesect.py"
CONFIG_FILE_NAME = "Genesect.ini"
USER_CONFIG_FILE_NAME = ".genesect.ini"
__version__ = "1.0.0"

MIN_PYTHON: Tuple[int, int] = (3, 9)
TESTED_PYTHON = ((3, 9), (3, 10), (3, 11), (3, 12))
MIN_IDA_VERSION = (8, 3)
TARGET_IDA_VERSIONS = ((8, 3), (8, 4), (9, 0), (9, 1), (9, 2))


@dataclass(frozen=True)
class CompatibilityResult:
    supported: bool
    current: Tuple[int, int]
    minimum: Tuple[int, int]
    message: str


def check_python_compatibility(version_info=None):
    """Check Python compatibility without importing IDA or Qt."""
    raw = version_info or tuple(sys.version_info)
    current = (int(raw[0]), int(raw[1]))
    supported = current >= MIN_PYTHON
    if supported:
        message = f"Python {current[0]}.{current[1]} meets the minimum requirement."
    else:
        message = (
            f"Python {current[0]}.{current[1]} is unsupported; "
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required."
        )
    return CompatibilityResult(supported, current, MIN_PYTHON, message)
