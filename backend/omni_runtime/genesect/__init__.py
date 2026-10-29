# -*- coding: utf-8 -*-
"""Genesect package metadata.

This module intentionally avoids GUI, configuration, and AI-client imports.
IDA console sessions import this package before a headless workspace export;
eager Qt initialization would prevent that export from starting.
"""

from genesect.metadata import PLUGIN_DISPLAY_NAME, PLUGIN_ID, __version__
