# Vendored OmniIDB Runtime

The `omni_idb` package, OmniIDB runtime scripts, and the locally installed Genesector engine dependency are vendored for MANTIS Binary Analysis Lab.

- Source snapshot: `C:\Users\radzi\Downloads\OmniIDB`
- Genesector runtime snapshot: the installed IDA 9.3 `plugins\genesect` package
- OmniIDB license: MIT, as declared by OmniIDB's `pyproject.toml`
- Genesector license: governed by the locally installed package; verify redistribution terms before publishing this snapshot
- Integration boundary: `backend/binary_lab.py`

The original Tkinter interface is retained in the package for upstream parity but is not used by MANTIS.
MANTIS applies a narrow batch-mode compatibility layer: the bundled runtime wins over IDA's auto-loaded plugin modules, IDA's Python directory is discoverable, and Qt-only base classes/signals receive inert fallbacks when `idat.exe` has no GUI runtime. The copied `Genesect.ini` contains no user credential or machine-specific cache path.
