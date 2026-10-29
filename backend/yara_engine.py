"""YARA engine abstraction for MANTIS.

All YARA features (Rule Explorer, Sample Scanner, Rule Workbench) go through
this module - no direct YARA-X / libyara calls elsewhere.

Primary engine: YARA-X (``yara_x`` package, official Python bindings).
Fallback: classic libyara via ``yara-python`` (used per-file/per-collection
when YARA-X rejects a rule, and when YARA-X is not installed).

Compatibility (measured Sep 2026 against data/yara-rules, 615 files):
594 files (~12,960 rules) compile under YARA-X. 21 files do not, e.g.
``magic`` module users (classic-only), bare ``hash`` identifiers, unused
patterns (E022), invalid regexes and assorted syntax errors. Those files are
retried on the classic engine instead of being silently dropped or rewritten.
"""

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger("mantis.yara.engine")

_LINE_RE = re.compile(r"line:(\d+):(\d+)")
_CLASSIC_LINE_RE = re.compile(r"line (\d+)", re.IGNORECASE)


class EngineCompileError(Exception):
    """Raised when compilation fails. Carries structured ``errors``."""

    def __init__(self, errors: List[Dict[str, Any]]):
        self.errors = errors
        super().__init__(errors[0].get("message", "compile error") if errors else "compile error")


class ScanTimeout(Exception):
    """A scan exceeded its timeout."""


def _parse_yarax_error(text: str, namespace: str = "") -> Dict[str, Any]:
    m = _LINE_RE.search(text or "")
    return {
        "namespace": namespace,
        "line": int(m.group(1)) if m else None,
        "column": int(m.group(2)) if m else None,
        "message": (text or "").strip()[:2000],
    }


def _parse_classic_error(text: str, namespace: str = "") -> Dict[str, Any]:
    m = _CLASSIC_LINE_RE.search(text or "")
    return {
        "namespace": namespace,
        "line": int(m.group(1)) if m else None,
        "column": None,
        "message": (text or "").strip()[:2000],
    }


class YaraEngine:
    """Engine interface. Compiled artifacts are opaque to callers."""

    name = "base"

    def compile(self, sources: Dict[str, str]):
        """Compile {namespace: source} into one scannable artifact.

        Raises EngineCompileError (with .errors) on failure.
        """
        raise NotImplementedError

    def validate(self, source: str) -> List[Dict[str, Any]]:
        """Return a (possibly empty) error list; never raises."""
        raise NotImplementedError

    def scan_bytes(self, compiled, data: bytes, timeout: int = 30) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def scan_file(self, compiled, path: str, timeout: int = 30) -> List[Dict[str, Any]]:
        raise NotImplementedError


class YaraXEngine(YaraEngine):
    name = "YARA-X"

    def compile(self, sources: Dict[str, str]):
        import yara_x

        compiler = yara_x.Compiler()
        errors: List[Dict[str, Any]] = []
        for namespace, src in sources.items():
            try:
                compiler.new_namespace(namespace)
                compiler.add_source(src or "")
            except yara_x.CompileError as e:
                errors.append(_parse_yarax_error(str(e), namespace))
            except Exception as e:  # pragma: no cover - defensive
                errors.append({"namespace": namespace, "line": None,
                               "column": None, "message": f"{type(e).__name__}: {e}"[:2000]})
        if errors:
            raise EngineCompileError(errors)
        try:
            return compiler.build()
        except yara_x.CompileError as e:
            raise EngineCompileError([_parse_yarax_error(str(e))])
        except Exception as e:  # pragma: no cover - defensive
            raise EngineCompileError([{"namespace": "", "line": None, "column": None,
                                       "message": f"{type(e).__name__}: {e}"[:2000]}])

    def validate(self, source: str) -> List[Dict[str, Any]]:
        import yara_x

        try:
            compiler = yara_x.Compiler()
            compiler.add_source(source or "")
            compiler.build()
            return []
        except yara_x.CompileError as e:
            return [_parse_yarax_error(str(e))]
        except Exception as e:  # pragma: no cover - defensive
            return [{"namespace": "", "line": None, "column": None,
                     "message": f"{type(e).__name__}: {e}"[:2000]}]

    @staticmethod
    def _normalize(rules_result) -> List[Dict[str, Any]]:
        out = []
        for m in rules_result.matching_rules or []:
            strings = []
            for p in m.patterns or []:
                for inst in p.matches or []:
                    strings.append({
                        "id": p.identifier,
                        "offset": int(inst.offset),
                        "length": int(inst.length),
                    })
            out.append({
                "rule": m.identifier,
                "namespace": m.namespace or "",
                "tags": list(m.tags or []),
                "meta": {str(k): v for k, v in (m.metadata or [])},
                "strings": strings,
            })
        return out

    def scan_bytes(self, compiled, data: bytes, timeout: int = 30):
        import yara_x

        scanner = yara_x.Scanner(compiled)
        if timeout and timeout > 0:
            scanner.set_timeout(int(timeout))
        try:
            return self._normalize(scanner.scan(data or b""))
        except yara_x.TimeoutError as e:
            raise ScanTimeout(str(e))

    def scan_file(self, compiled, path: str, timeout: int = 30):
        import yara_x

        scanner = yara_x.Scanner(compiled)
        if timeout and timeout > 0:
            scanner.set_timeout(int(timeout))
        try:
            return self._normalize(scanner.scan_file(path))
        except yara_x.TimeoutError as e:
            raise ScanTimeout(str(e))


class ClassicYaraEngine(YaraEngine):
    name = "classic-libyara"

    def compile(self, sources: Dict[str, str]):
        import yara

        try:
            return yara.compile(sources={ns: (src or "") for ns, src in sources.items()})
        except yara.Error as e:
            raise EngineCompileError([_parse_classic_error(str(e))])
        except Exception as e:  # pragma: no cover - defensive
            raise EngineCompileError([{"namespace": "", "line": None, "column": None,
                                       "message": f"{type(e).__name__}: {e}"[:2000]}])

    def validate(self, source: str) -> List[Dict[str, Any]]:
        import yara

        try:
            yara.compile(source=source or "")
            return []
        except yara.Error as e:
            return [_parse_classic_error(str(e))]
        except Exception as e:  # pragma: no cover - defensive
            return [{"namespace": "", "line": None, "column": None,
                     "message": f"{type(e).__name__}: {e}"[:2000]}]

    @staticmethod
    def _normalize(matches) -> List[Dict[str, Any]]:
        out = []
        for m in matches or []:
            strings = []
            for s in m.strings or []:
                for inst in s.instances or []:
                    strings.append({
                        "id": s.identifier,
                        "offset": int(inst.offset),
                        "length": int(inst.matched_length),
                    })
            meta = m.meta or {}
            out.append({
                "rule": m.rule,
                "namespace": m.namespace or "",
                "tags": list(m.tags or []),
                "meta": {str(k): v for k, v in meta.items()} if isinstance(meta, dict) else {},
                "strings": strings,
            })
        return out

    def _timeout_kwargs(self, timeout: int) -> Dict[str, Any]:
        return {"timeout": int(timeout)} if timeout and timeout > 0 else {}

    def scan_bytes(self, compiled, data: bytes, timeout: int = 30):
        import yara

        try:
            return self._normalize(compiled.match(data=data or b"", **self._timeout_kwargs(timeout)))
        except yara.TimeoutError as e:
            raise ScanTimeout(str(e))

    def scan_file(self, compiled, path: str, timeout: int = 30):
        import yara

        try:
            return self._normalize(compiled.match(filepath=path, **self._timeout_kwargs(timeout)))
        except yara.TimeoutError as e:
            raise ScanTimeout(str(e))


def yara_x_available() -> bool:
    try:
        import yara_x  # noqa: F401
        return True
    except Exception:
        return False


def classic_available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except Exception:
        return False


def get_engine(prefer: str = "yarax") -> YaraEngine:
    """Primary YARA-X unless unavailable (or classic explicitly preferred)."""
    if prefer == "classic":
        if classic_available():
            return ClassicYaraEngine()
        raise RuntimeError("classic yara engine requested but yara-python is not installed")
    if yara_x_available():
        return YaraXEngine()
    if classic_available():
        logger.warning("YARA-X not installed; falling back to classic libyara")
        return ClassicYaraEngine()
    raise RuntimeError("no YARA engine available (install yara-x or yara-python)")


def available_engines() -> List[str]:
    out = []
    if yara_x_available():
        out.append("YARA-X")
    if classic_available():
        out.append("classic-libyara")
    return out
