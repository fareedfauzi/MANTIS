"""Markdown, HTML and PDF report rendering (modelled on REAI's reporting engine).

``render_reports`` turns an ``omni-report-v1`` model (see :mod:`omni_idb.report_model`)
into ``report.md``, ``report.html`` and ``report.pdf``. Only the standard library is
required; if ``reportlab`` is installed the PDF uses it, otherwise a built-in writer
produces a clean text PDF.
"""

from __future__ import annotations

import html
import json
import re
import textwrap
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from omni_idb import report_model as rm
except ImportError:
    rm = None

VERDICTS = {"benign", "interesting", "suspicious", "malicious", "core functionality", "core"}


# ---------------------------------------------------------------- markdown
def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\r", "").replace("\n", " ").strip()


def _table(headers: List[str], rows: List[List[Any]]) -> List[str]:
    if not rows:
        return []
    lines = ["| " + " | ".join(_md(h) for h in headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(_md(c) for c in row) + " |")
    lines.append("")
    return lines


def demote_headings(markdown: str, by: int) -> str:
    out, in_code = [], False
    for line in str(markdown).splitlines():
        if line.startswith("```"):
            in_code = not in_code
        elif not in_code:
            m = re.match(r"^(#{1,6})(\s+.*)$", line)
            if m:
                line = "#" * min(6, len(m.group(1)) + by) + m.group(2)
        out.append(line)
    return "\n".join(out)


def _mermaid_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_ .:/()-]", "_", str(value))[:60].replace('"', "'")


def render_markdown(model: Dict[str, Any]) -> str:
    sample = model.get("sample", {})
    L: List[str] = ["# Analysis Report: %s" % _md(sample.get("filename", "sample")), ""]

    def section(title: str, level: int = 2) -> None:
        L.extend(["#" * level + " " + title, ""])

    section("Malware Category")
    badges = ", ".join(model.get("badges", []))
    category = model.get("category") or "Unclassified"
    L.extend([category + (" (%s)" % badges if badges else ""), ""])

    if model.get("executive_summary"):
        section("Executive Summary")
        L.extend([model["executive_summary"], ""])
        if model.get("nutshell"):
            L.extend(["This report in a nutshell:", ""] + ["- %s" % _md(p) for p in model["nutshell"]] + [""])

    section("Sample Profile")
    rows = [
        ("File name", sample.get("filename")), ("File size", sample.get("size")),
        ("MD5", sample.get("md5")), ("SHA256", sample.get("sha256")),
        ("File type", sample.get("file_type")), ("Architecture", sample.get("architecture")),
        ("Bitness", sample.get("bitness")), ("Image base", sample.get("image_base")),
        ("Entry point", sample.get("entry")), ("IDA version", sample.get("ida_version")),
        ("Analysis timestamp", model.get("generated_at")),
    ]
    L.extend(_table(["Field", "Value"], [[k, v] for k, v in rows if v not in (None, "")]))

    has_tech = model.get("technical_analysis") or model.get("execution_flow") or model.get("capabilities") or model.get("key_functions")
    if has_tech:
        section("Technical Analysis")
        if model.get("technical_analysis"):
            L.extend([demote_headings(model["technical_analysis"], 2), ""])
        if model.get("execution_flow"):
            section("Execution Flow Overview", 3)
            ids = []
            L.extend(["```mermaid", "flowchart TD"])
            for i, step in enumerate(model["execution_flow"][:20]):
                L.append('    N%d["%s"]' % (i, _mermaid_label(step.get("stage", ""))))
                ids.append("N%d" % i)
            if len(ids) > 1:
                L.append("    " + " --> ".join(ids))
            L.extend(["```", ""])
            L.extend(_table(["Stage", "Description", "Evidence"],
                            [[s.get("stage"), s.get("description"), s.get("evidence")] for s in model["execution_flow"]]))
        if model.get("capabilities"):
            section("Capabilities", 3)
            L.extend(_table(["Capability", "What the evidence supports", "Evidence"],
                            [[c.get("name"), c.get("description"), c.get("evidence")] for c in model["capabilities"]]))


    if model.get("conclusion"):
        section("Conclusion")
        L.extend([model["conclusion"], ""])

    if model.get("iocs"):
        section("Indicators of Compromise")
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for ioc in model["iocs"]:
            by_type.setdefault(str(ioc.get("type", "other")), []).append(ioc)
        for itype in sorted(by_type):
            section(itype.replace("_", " ").title(), 3)
            L.extend(_table(["Indicator", "Role", "Context"],
                            [["`%s`" % _md(i.get("value")), i.get("role"), i.get("context")] for i in by_type[itype]]))
    hashes = [(k, sample.get(k)) for k in ("md5", "sha256") if sample.get(k)]
    if hashes:
        section("Hashes", 3)
        L.extend(_table(["Algorithm", "Value"], [[k.upper(), "`%s`" % v] for k, v in hashes]))

    rule = rm.yara_rule(model) if rm and hasattr(rm, 'yara_rule') else ''
    if rule:
        section("YARA Rules")
        L.extend(["```yara", rule, "```", ""])

    if model.get("mitre"):
        section("MITRE ATT&CK Mappings")
        L.extend(_table(["Tactic", "Technique", "ID", "Evidence"],
                        [[m.get("tactic"), m.get("technique"), m.get("id"), m.get("evidence")] for m in model["mitre"]]))

    if model.get("key_functions"):
        is_dn = bool(
            model.get("is_dotnet")
            or "dotnet" in str(sample.get("file_type", "")).lower()
            or any(f.get("type_namespace") for f in model["key_functions"])
        )
        if is_dn:
            section("Key Methods for Decompiler Navigation (dnSpy / ILSpy)")
            L.append("The following table prioritizes critical managed classes and methods for reverse engineers to inspect in dnSpy or ILSpy. Use the method tokens or locations to locate decompiled logic.")
            L.append("")
            headers = ["Type / Namespace", "Method Name", "Location / Token", "Classification", "Assessment & What to Inspect in Decompiler"]
            rows = []
            for f in model["key_functions"]:
                t_ns = "`%s`" % _md(f.get("type_namespace") or f.get("namespace") or "-")
                fn_name = "`%s`" % _md(f.get("name", ""))
                loc = "`%s`" % _md(f.get("location") or f.get("token") or f.get("address") or "-")
                verd = f.get("verdict") or "Suspicious"
                guidance = f.get("triage_guidance") or f.get("summary") or "Inspect method logic in decompiler."
                rows.append([t_ns, fn_name, loc, verd, guidance])
            L.extend(_table(headers, rows))
        else:
            section("Key Functions for Reverse Engineering & IDB Navigation")
            L.append("The following table prioritizes critical subroutines for reverse engineers to inspect in IDA Pro. Use the function addresses to jump directly (`G` in IDA) to relevant disassembly and decompiled logic.")
            L.append("")
            headers = ["Address", "Function Name", "Original Name", "Classification", "Assessment & What to Inspect in IDB"]
            rows = []
            for f in model["key_functions"]:
                addr = "`%s`" % _md(f.get("address", "")) if f.get("address") else "-"
                fn_name = "`%s`" % _md(f.get("name", ""))
                orig = "`%s`" % _md(f.get("original_name")) if f.get("original_name") and f.get("original_name") != "-" else "-"
                verd = f.get("verdict") or "Suspicious"
                guidance = f.get("triage_guidance") or f.get("summary") or "Inspect subroutine logic in IDA."
                rows.append([addr, fn_name, orig, verd, guidance])
            L.extend(_table(headers, rows))
        for fn in model["key_functions"]:
            extras = []
            if fn.get("behaviors"):
                extras.append("- **Observed Behaviors**: " + "; ".join(_md(b) for b in fn["behaviors"]))
            if fn.get("apis"):
                extras.append("- **APIs Referenced**: " + ", ".join("`%s`" % a for a in fn["apis"]))
            if extras:
                L.extend(["#### %s (%s)" % (_md(fn.get("name")), _md(fn.get("address", ""))), ""] + extras + [""])

    notes = model.get("analysis_gaps") or model.get("analyst_notes") or model.get("imports") or model.get("strings") \
        or model.get("renamed_functions") or model.get("findings") or model.get("agent_report")
    if notes:
        section("Notes For Analyst")
        if model.get("analysis_gaps"):
            section("Analysis Gaps", 3)
            L.extend(["- %s" % _md(g) for g in model["analysis_gaps"]] + [""])
        if model.get("analyst_notes"):
            section("Suggested Next Steps", 3)
            L.extend([demote_headings(model["analyst_notes"], 2), ""])
        if model.get("imports"):
            section("Suspicious Imports", 3)
            L.extend(_table(["API Name", "Category", "Module"],
                            [[i.get("name"), i.get("category"), i.get("module", "")] for i in model["imports"][:150]]))
        if model.get("strings"):
            section("Strings Analysis", 3)
            L.extend(_table(["Address", "String"], [[s.get("address"), s.get("value", "")[:140]] for s in model["strings"][:60]]))
        if model.get("renamed_functions"):
            section("Function Analysis", 3)
            L.extend(_table(["Original", "Renamed to", "Address"],
                            [[r.get("old"), r.get("new"), r.get("address")] for r in model["renamed_functions"][:300]]))
        if model.get("findings"):
            section("Verified Findings", 3)
            for i, f in enumerate(model["findings"], 1):
                L.append("#### %d. %s" % (i, _md(f.get("claim"))))
                L.append("")
                L.append("- **Confidence**: `%s`" % str(f.get("confidence", "")).upper())
                if f.get("tags"):
                    L.append("- **Tags**: %s" % ", ".join(_md(t) for t in f["tags"]))
                for ev in f.get("evidence") or []:
                    L.append("  - `%s`" % _md(ev))
                L.append("")
        if model.get("agent_report"):
            section("Agent Investigation Notes", 3)
            L.extend([demote_headings(model["agent_report"], 3), ""])

    section("Appendix")
    stats = model.get("stats", {})
    prov = model.get("provider", {})
    rows = [("Report schema", model.get("schema")), ("AI synthesis", model.get("synthesis_status")),
            ("Primary provider", prov.get("primary")), ("Providers used", ", ".join(prov.get("used", [])))]
    usage = model.get("usage")
    if usage and usage.get("total_tokens"):
        cost_str = " (~$%.3f)" % usage["estimated_cost_usd"] if usage.get("estimated_cost_usd", 0) > 0 else ""
        rows.append(("Tokens (est.)", "%d (%d billable)%s" % (usage.get("total_tokens", 0), usage.get("billable_tokens", 0), cost_str)))
    cache = model.get("cache")
    if cache and cache.get("total_hits"):
        rows.append(("Cache hits", str(cache.get("total_hits", 0))))
    rows += [(k.replace("_", " ").capitalize(), v) for k, v in sorted(stats.items())]
    L.extend(_table(["Field", "Value"], [[k, v] for k, v in rows if v not in (None, "")]))
    if prov.get("fallback_events"):
        section("Provider fallback events", 3)
        L.extend(_table(["From", "To", "Reason"], [[e.get("from"), e.get("to"), e.get("reason")] for e in prov["fallback_events"]]))
    if sample.get("original_idb") or sample.get("analyzed_idb"):
        L.extend(["Companion databases: original `%s`, analyzed `%s`." % (
            sample.get("original_idb", "?"), sample.get("analyzed_idb", "?")), ""])
    return "\n".join(L).rstrip() + "\n"


# ---------------------------------------------------------------- markdown parsing
Block = Tuple[Any, ...]


def parse_blocks(markdown: str) -> List[Block]:
    blocks: List[Block] = []
    lines = markdown.splitlines()
    i, n = 0, len(lines)
    para: List[str] = []

    def flush() -> None:
        if para:
            blocks.append(("p", " ".join(s.strip() for s in para)))
            para.clear()

    while i < n:
        line = lines[i]
        if line.startswith("```"):
            flush()
            lang, buf = line[3:].strip().lower(), []
            i += 1
            while i < n and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            blocks.append(("code", lang, "\n".join(buf)))
        elif line.strip().startswith("|"):
            flush()
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                if not re.match(r"^\|(?:\s*:?-{2,}:?\s*\|)+\s*$", lines[i].strip()):
                    cells = [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", lines[i].strip().strip("|"))]
                    rows.append(cells)
                i += 1
            i -= 1
            if rows:
                blocks.append(("table", rows[0], rows[1:]))
        elif re.match(r"^\s*#{1,6}\s", line):
            flush()
            m = re.match(r"^\s*(#{1,6})\s+(.*)$", line)
            blocks.append(("h", len(m.group(1)), m.group(2).strip()))
        elif re.match(r"^\s*(?:[-*]|\d+\.)\s+", line):
            flush()
            items = []
            while i < n and re.match(r"^\s*(?:[-*]|\d+\.)\s+", lines[i]):
                indent = len(lines[i]) - len(lines[i].lstrip())
                items.append((1 if indent >= 2 else 0, re.sub(r"^\s*(?:[-*]|\d+\.)\s+", "", lines[i])))
                i += 1
            i -= 1
            blocks.append(("ul", items))
        elif not line.strip():
            flush()
        else:
            para.append(line)
        i += 1
    flush()
    return blocks


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


# ---------------------------------------------------------------- HTML
def _inline_html(text: str) -> str:
    out = html.escape(text, quote=False)
    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2" target="_blank" rel="noopener">\1</a>', out)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    return out


def _cell_html(text: str) -> str:
    cleaned = text.strip()
    key = cleaned.lower()
    if key in VERDICTS or "core" in key:
        cls = "core-functionality" if "core" in key else key
        return '<span class="verdict %s">%s</span>' % (cls, cleaned.upper())
    return _inline_html(text)


_CSS = """
:root{--bg:#0f1218;--panel:#171b24;--line:#2a3040;--text:#e2e8f0;--muted:#94a3b8;--accent:#60a5fa;--code:#0b0e14}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 "Segoe UI",Arial,sans-serif}
.layout{display:flex;max-width:1400px;margin:0 auto}
nav{position:sticky;top:0;align-self:flex-start;height:100vh;overflow:auto;width:260px;padding:28px 18px;border-right:1px solid var(--line)}
nav h2{font-size:12px;letter-spacing:.12em;color:var(--muted);margin:0 0 12px}nav ul{list-style:none;margin:0;padding:0}
nav a{display:block;padding:5px 8px;border-radius:6px;color:var(--muted);text-decoration:none;font-size:14px}nav a:hover{background:var(--panel);color:#fff}
main{flex:1;min-width:0;padding:32px 44px 80px}
h1{margin:0 0 6px;font-size:28px}.sub{color:var(--muted);margin-bottom:18px;word-break:break-all}
.badges{margin:8px 0 20px}.badge{display:inline-block;background:#1e3a8a;color:#bfdbfe;border-radius:12px;padding:2px 10px;margin-right:6px;font-size:12px;font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .l{display:block;font-size:11px;letter-spacing:.1em;color:var(--muted)}.card .v{display:block;font-size:16px;font-weight:600;margin-top:4px;word-break:break-word}
section{margin-bottom:34px}h2.t{font-size:21px;border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:0;color:#f1f5f9}
h3{font-size:17px;color:#cbd5e1;margin:22px 0 8px}h4,h5,h6{font-size:14px;color:var(--accent);margin:16px 0 6px}
p{margin:8px 0}ul{margin:6px 0 10px 22px;padding:0}li{margin:3px 0}
code{background:var(--code);color:#7dd3fc;padding:1px 5px;border-radius:4px;font-family:Consolas,monospace;font-size:13px;word-break:break-all}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow:auto}pre code{padding:0;background:none;color:#cbd5e1;word-break:normal}
.tw{overflow-x:auto;margin:12px 0}table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}th{background:#1c2230;color:#cbd5e1}tr:nth-child(even) td{background:#141821}
.verdict{border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700}.benign{background:#14532d;color:#86efac}.interesting{background:#1e3a8a;color:#93c5fd}
.suspicious{background:#78350f;color:#fed7aa}.malicious{background:#7f1d1d;color:#fecaca}.core-functionality{background:#1e293b;color:#38bdf8;border:1px solid #0284c7}
pre.mermaid{background:var(--panel);text-align:center}
@media print{body{background:#fff;color:#111}nav{display:none}.card,pre,th,td{border-color:#ccc}code,pre{background:#f4f4f4;color:#111}}
@media(max-width:900px){nav{display:none}main{padding:20px}}
"""


def render_html(markdown: str, model: Dict[str, Any]) -> str:
    sample = model.get("sample", {})
    blocks = parse_blocks(markdown)
    nav = [b[2] for b in blocks if b[0] == "h" and b[1] == 2]
    if not nav:
        nav = [b[2] for b in blocks if b[0] == "h" and b[1] in (1, 2, 3)]
    nav_html = "\n".join('<li><a href="#%s">%s</a></li>' % (slugify(t), html.escape(t)) for t in nav)
    stats = model.get("stats", {})
    sha = sample.get("sha256")
    if not sha:
        sha_m = re.search(r"\b([a-fA-F0-9]{64})\b", markdown)
        if sha_m:
            sha = sha_m.group(1).lower()

    # Count tables / key functions from blocks if not in model
    key_fn_count = 0
    for b in blocks:
        if b[0] == "table":
            header_strs = " ".join(str(c).lower() for c in b[1])
            if "function" in header_strs or "method" in header_strs:
                key_fn_count += len(b[2])

    cards = [("CLASSIFICATION", model.get("category") or "Malware Analysis Report")]
    platform = " ".join(str(x) for x in (sample.get("file_type"), sample.get("architecture")) if x)
    if platform:
        cards.append(("PLATFORM", platform))
    fn_renamed = stats.get("functions_renamed", len(model.get("renamed_functions", []))) or key_fn_count
    if fn_renamed:
        cards.append(("KEY FUNCTIONS", fn_renamed))
    if model.get("findings"):
        cards.append(("VERIFIED FINDINGS", len(model["findings"])))
    if model.get("iocs"):
        cards.append(("INDICATORS", len(model["iocs"])))
    prov = ", ".join(model.get("provider", {}).get("used", []))
    if prov:
        cards.append(("AI PROVIDER", prov))

    cards_html = "".join('<div class="card"><span class="l">%s</span><span class="v">%s</span></div>' % (l, html.escape(str(v))) for l, v in cards)
    badges_html = "".join('<span class="badge">%s</span>' % html.escape(b) for b in model.get("badges", []))

    body: List[str] = []
    in_section = False
    has_mermaid = False
    for b in blocks:
        kind = b[0]
        if kind == "h":
            level, text = b[1], b[2]
            if level == 1:
                continue  # rendered in the page header
            if level == 2:
                if in_section:
                    body.append("</section>")
                body.append('<section id="%s"><h2 class="t">%s</h2>' % (slugify(text), html.escape(text)))
                in_section = True
            else:
                body.append("<h%d id=\"%s\">%s</h%d>" % (min(level, 6), slugify(text), _inline_html(text), min(level, 6)))
        elif kind == "p":
            body.append("<p>%s</p>" % _inline_html(b[1]))
        elif kind == "ul":
            body.append("<ul>" + "".join('<li%s>%s</li>' % (' style="margin-left:18px"' if lvl else "", _inline_html(t)) for lvl, t in b[1]) + "</ul>")
        elif kind == "code":
            lang, text = b[1], b[2]
            if lang == "mermaid":
                has_mermaid = True
                body.append('<pre class="mermaid">%s</pre>' % html.escape(text))
            else:
                body.append('<pre><code class="lang-%s">%s</code></pre>' % (html.escape(lang), html.escape(text)))
        elif kind == "table":
            head = "".join("<th>%s</th>" % _inline_html(c) for c in b[1])
            rows = "".join("<tr>" + "".join("<td>%s</td>" % _cell_html(c) for c in r) + "</tr>" for r in b[2])
            body.append('<div class="tw"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (head, rows))
    if in_section:
        body.append("</section>")
    mermaid = ('<script type="module">import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";'
               'mermaid.initialize({startOnLoad:true,theme:"dark"});</script>') if has_mermaid else ""
    h1_candidates = [b[2] for b in blocks if b[0] == "h" and b[1] == 1]
    title_text = str(model.get("title") or sample.get("filename") or (h1_candidates[0] if h1_candidates else "Analysis Report"))
    title = html.escape(title_text)
    sha_html = ('<div class="sub">SHA256 %s</div>' % html.escape(sha)) if sha else ""
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s - Analysis Report</title><style>%s</style></head>
<body><div class="layout"><nav><h2>CONTENTS</h2><ul>%s</ul></nav>
<main><h1>%s</h1>%s<div class="badges">%s</div><div class="cards">%s</div>
%s
</main></div>%s</body></html>
""" % (title, _CSS, nav_html, title, sha_html, badges_html, cards_html, "\n".join(body), mermaid)


# ---------------------------------------------------------------- PDF
def _pdf_text(value: str) -> str:
    for a, b in (("\u2192", "->"), ("\u2022", "-"), ("\u2013", "-"), ("\u2014", "-"), ("\u2018", "'"), ("\u2019", "'"),
                 ("\u201c", '"'), ("\u201d", '"'), ("\u2713", "OK"), ("\u2717", "X"), ("\u2026", "...")):
        value = value.replace(a, b)
    return value


def render_pdf(markdown: str, model: Dict[str, Any], output: Path) -> str:
    """Write the PDF; returns the engine used (``reportlab`` or ``builtin``)."""
    blocks = parse_blocks(markdown)
    try:
        import reportlab  # noqa: F401
    except ImportError:
        _render_pdf_builtin(blocks, model, output)
        return "builtin"
    try:
        _render_pdf_reportlab(blocks, model, output, markdown=markdown)
        return "reportlab"
    except Exception as rl_err:
        _render_pdf_builtin(blocks, model, output)
        return f"builtin (fallback due to reportlab error: {rl_err})"


def _rl_inline(text: str) -> str:
    cleaned = text.strip().lower()
    if cleaned == "malicious":
        return '<font color="#DC2626"><b>MALICIOUS</b></font>'
    if cleaned == "suspicious":
        return '<font color="#D97706"><b>SUSPICIOUS</b></font>'
    if cleaned in ("core functionality", "core"):
        return '<font color="#0284C7"><b>CORE FUNCTIONALITY</b></font>'
    out = html.escape(_pdf_text(text), quote=False)
    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<font color="#1D4ED8"><u>\1</u></font>', out)
    out = re.sub(r"`([^`]+)`", r'<font face="Courier" color="#2B6CB0">\1</font>', out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", out)
    return out


def _render_pdf_reportlab(blocks: List[Block], model: Dict[str, Any], output: Path, markdown: str = "") -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = ParagraphStyle("B", parent=styles["Normal"], fontSize=9.5, leading=13.5, textColor=colors.HexColor("#2D3748"), spaceAfter=6, wordWrap="CJK")
    cell = ParagraphStyle("C", parent=body, fontSize=8, leading=10.5, spaceAfter=0, wordWrap="CJK")
    head = ParagraphStyle("H", parent=cell, fontName="Helvetica-Bold", textColor=colors.HexColor("#1A365D"))
    code = ParagraphStyle("K", parent=styles["Code"], fontSize=7.5, leading=9.5, textColor=colors.HexColor("#2B6CB0"),
                          backColor=colors.HexColor("#F4F6F8"), borderPadding=4, spaceAfter=8)
    title = ParagraphStyle("T", parent=styles["Title"], fontSize=22, leading=26, textColor=colors.HexColor("#0D131C"), alignment=0)
    hs = {
        2: ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, leading=18, textColor=colors.HexColor("#1A365D"), spaceBefore=14, keepWithNext=True),
        3: ParagraphStyle("H3", parent=styles["Heading3"], fontSize=11.5, leading=15, textColor=colors.HexColor("#2D3748"), spaceBefore=10, keepWithNext=True),
        4: ParagraphStyle("H4", parent=styles["Heading4"], fontSize=10, leading=13, textColor=colors.HexColor("#4A5568"), spaceBefore=8, keepWithNext=True),
    }
    sample = model.get("sample", {})
    width = letter[0] - 80
    h1_candidates = [b[2] for b in blocks if b[0] == "h" and b[1] == 1]
    title_text = str(model.get("title") or sample.get("filename") or (h1_candidates[0] if h1_candidates else "sample"))
    sha = sample.get("sha256")
    if not sha and markdown:
        sha_m = re.search(r"\b([a-fA-F0-9]{64})\b", markdown)
        if sha_m:
            sha = sha_m.group(1).lower()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#718096"))
        canvas.drawString(40, 22, "MANTIS Binary Lab analysis report - %s" % _pdf_text(str(sample.get("filename") or title_text)))
        canvas.drawRightString(letter[0] - 40, 22, "Page %d" % doc.page)
        canvas.restoreState()

    story: List[Any] = [Paragraph("<b>MANTIS BINARY ANALYSIS REPORT</b>", body), Paragraph(html.escape(_pdf_text(title_text)), title),
                        Paragraph("<b>Classification:</b> %s" % html.escape(_pdf_text(str(model.get("category") or "Unclassified"))), body)]
    if sha:
        story.append(Paragraph("<b>SHA256:</b> <font face='Courier'>%s</font>" % html.escape(str(sha)), body))
    story.append(Spacer(1, 10))

    for b in blocks:
        kind = b[0]
        if kind == "h":
            if b[1] == 1:
                continue
            story.append(Paragraph(_rl_inline(b[2]), hs.get(min(b[1], 4), hs[4])))
        elif kind == "p":
            story.append(Paragraph(_rl_inline(b[1]), body))
        elif kind == "ul":
            for lvl, text in b[1]:
                story.append(Paragraph("&bull; " + _rl_inline(text), ParagraphStyle("L", parent=body, leftIndent=12 + 12 * lvl, firstLineIndent=-8, spaceAfter=2)))
            story.append(Spacer(1, 4))
        elif kind == "code":
            lang, text = b[1], b[2]
            if lang == "mermaid":
                text = "\n".join(l.strip() for l in text.splitlines() if "-->" in l)
                story.append(Paragraph("<b>Execution flow:</b>", body))
            lines = []
            for l in _pdf_text(text).splitlines():
                lines.extend(textwrap.wrap(l, 110, replace_whitespace=False, drop_whitespace=False) or [""])
            story.append(Preformatted("\n".join(lines), code))
        elif kind == "table":
            ncols = len(b[1])
            if ncols == 0:
                continue
            data = [[Paragraph(_rl_inline(c), head) for c in b[1]]]
            for r in b[2]:
                r = (r + [""] * ncols)[:ncols]
                data.append([Paragraph(_rl_inline(c), cell) for c in r])
            col_lens = [max(len(str(row[c])) if c < len(row) else 1 for row in [b[1]] + list(b[2])) for c in range(ncols)]
            total_len = sum(col_lens) or 1
            col_widths = [max(45, (cl / total_len) * width) for cl in col_lens]
            scale = width / sum(col_widths)
            col_widths = [w * scale for w in col_widths]
            t = Table(data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
            ]))
            story.extend([t, Spacer(1, 8)])
    SimpleDocTemplate(str(output), pagesize=letter, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40,
                      title="%s analysis report" % sample.get("filename", "sample")).build(story, onFirstPage=footer, onLaterPages=footer)


class _PdfDoc:
    """Tiny dependency-free PDF writer: Helvetica / Helvetica-Bold / Courier text pages."""

    W, H, MARGIN = 612, 792, 54

    def __init__(self, footer: str):
        self.footer = footer
        self.pages: List[List[str]] = [[]]
        self.y = self.H - self.MARGIN

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = self.H - self.MARGIN

    def line(self, text: str, font: str = "F1", size: float = 10, color=(0.17, 0.2, 0.28), indent: float = 0, gap: float = 0) -> None:
        lead = size * 1.35
        self.y -= gap
        if self.y - lead < self.MARGIN + 14:
            self._new_page()
        self.y -= lead
        esc = _pdf_text(text).encode("cp1252", "replace").decode("cp1252").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        self.pages[-1].append("BT /%s %.1f Tf %.2f %.2f %.2f rg %.1f %.1f Td (%s) Tj ET" % (font, size, color[0], color[1], color[2], self.MARGIN + indent, self.y, esc))

    def wrapped(self, text: str, font: str, size: float, color, indent: float = 0, gap: float = 0, factor: float = 0.52) -> None:
        chars = max(20, int((self.W - 2 * self.MARGIN - indent) / (size * factor)))
        for i, part in enumerate(textwrap.wrap(_pdf_text(text), chars, break_long_words=True) or [""]):
            self.line(part, font, size, color, indent, gap if i == 0 else 0)

    def save(self, output: Path) -> None:
        objs: List[bytes] = [b"", b"",
                             b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                             b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
                             b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"]
        page_ids = []
        for number, ops in enumerate(self.pages, 1):
            foot = "BT /F1 8 Tf 0.45 0.5 0.55 rg %d 28 Td (%s - page %d of %d) Tj ET" % (
                self.MARGIN, _pdf_text(self.footer).replace("(", "").replace(")", "").replace("\\", ""), number, len(self.pages))
            stream = "\n".join(ops + [foot]).encode("cp1252", "replace")
            content_id = len(objs) + 2
            page_ids.append(len(objs) + 1)
            objs.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>"
                         % (self.W, self.H, content_id)).encode())
            objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
        objs[1] = ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join("%d 0 R" % p for p in page_ids), len(page_ids))).encode()
        data = bytearray(b"%PDF-1.4\n")
        offsets = []
        for i, obj in enumerate(objs, 1):
            offsets.append(len(data))
            data += ("%d 0 obj\n" % i).encode() + obj + b"\nendobj\n"
        xref = len(data)
        data += ("xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)).encode()
        for off in offsets:
            data += ("%010d 00000 n \n" % off).encode()
        data += ("trailer << /Root 1 0 R /Size %d >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)).encode()
        output.write_bytes(bytes(data))


def _plain(text: str) -> str:
    return re.sub(r"\*\*([^*]+)\*\*", r"\1", re.sub(r"`([^`]+)`", r"\1", text))


def _render_pdf_builtin(blocks: List[Block], model: Dict[str, Any], output: Path) -> None:
    sample = model.get("sample", {})
    h1_candidates = [b[2] for b in blocks if b[0] == "h" and b[1] == 1]
    title_text = str(model.get("title") or sample.get("filename") or (h1_candidates[0] if h1_candidates else "sample"))
    doc = _PdfDoc("MANTIS Binary Lab analysis report - %s" % (sample.get("filename") or title_text))
    navy, slate, blue = (0.1, 0.21, 0.36), (0.17, 0.2, 0.28), (0.17, 0.42, 0.69)
    doc.line("MANTIS BINARY ANALYSIS REPORT", "F2", 9, (0.4, 0.45, 0.5))
    doc.wrapped(title_text, "F2", 20, (0.05, 0.07, 0.11), gap=4, factor=0.55)
    doc.wrapped("Classification: %s" % (model.get("category") or "Unclassified"), "F1", 10, slate, gap=4)
    doc.wrapped("SHA256: %s" % sample.get("sha256", "n/a"), "F3", 8, slate, gap=2, factor=0.6)
    for b in blocks:
        kind = b[0]
        if kind == "h":
            if b[1] == 1:
                continue
            size = {2: 14, 3: 11.5}.get(b[1], 10)
            doc.wrapped(_plain(b[2]), "F2", size, navy if b[1] <= 3 else blue, gap=12 if b[1] == 2 else 8)
        elif kind == "p":
            doc.wrapped(_plain(b[1]), "F1", 9.5, slate, gap=4)
        elif kind == "ul":
            for lvl, text in b[1]:
                doc.wrapped("- " + _plain(text), "F1", 9.5, slate, indent=10 + 12 * lvl, gap=1)
        elif kind == "code":
            text = b[2]
            if b[1] == "mermaid":
                doc.line("Execution flow:", "F2", 9, slate, gap=4)
                text = "\n".join(l.strip() for l in text.splitlines() if "-->" in l)
            for l in text.splitlines():
                doc.wrapped(l, "F3", 7.5, blue, indent=8, factor=0.6)
        elif kind == "table":
            doc.wrapped(" | ".join(_plain(c) for c in b[1]), "F2", 8.5, navy, gap=5, factor=0.55)
            for r in b[2]:
                doc.wrapped(" | ".join(_plain(c) for c in r), "F1", 8.5, slate, indent=6, gap=2, factor=0.5)
    doc.save(output)


# ---------------------------------------------------------------- driver
def render_reports(
    model: Any,
    out_dir: Path | str,
    log: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Dict[str, str]:
    """Render ``report.md/html/pdf`` into ``out_dir``. ``model`` is a dict or a JSON file path."""
    logger = log_fn or log or (lambda _m: None)
    if not isinstance(model, dict):
        model = json.loads(Path(model).read_text(encoding="utf-8"))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}
    markdown = render_markdown(model)
    (out / "report.md").write_text(markdown, encoding="utf-8")
    paths["markdown"] = str(out / "report.md")
    (out / "report.html").write_text(render_html(markdown, model), encoding="utf-8")
    paths["html"] = str(out / "report.html")
    try:
        engine = render_pdf(markdown, model, out / "report.pdf")
        paths["pdf"] = str(out / "report.pdf")
        logger("PDF rendered with %s engine" % engine)
    except Exception as error:  # noqa: BLE001 - PDF is best effort, md/html are already written
        logger("PDF rendering failed: %s" % error)
    return paths


def render_markdown_deliverables(
    markdown: str,
    out_dir: Path | str,
    model: Optional[Dict[str, Any]] = None,
    base_name: str = "report",
    log_fn: Optional[Callable[[str], None]] = None,
) -> Dict[str, str]:
    """Render raw markdown text into {base_name}.md, {base_name}.html, and {base_name}.pdf in out_dir."""
    logger = log_fn or (lambda _m: None)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: Dict[str, str] = {}
    md_file = out / f"{base_name}.md"
    html_file = out / f"{base_name}.html"
    pdf_file = out / f"{base_name}.pdf"

    md_file.write_text(markdown, encoding="utf-8")
    paths["markdown"] = str(md_file)

    model_dict = dict(model or {})
    try:
        html_content = render_html(markdown, model_dict)
        html_file.write_text(html_content, encoding="utf-8")
        paths["html"] = str(html_file)
    except Exception as error:
        logger(f"HTML rendering failed ({html_file.name}): {error}")

    try:
        engine = render_pdf(markdown, model_dict, pdf_file)
        paths["pdf"] = str(pdf_file)
        logger(f"PDF rendered with {engine} engine ({pdf_file.name})")
    except Exception as error:
        logger(f"PDF rendering failed ({pdf_file.name}): {error}")

    return paths


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Render Markdown into styled HTML and vector PDF deliverables.")
    parser.add_argument("markdown_file", help="Path to markdown file (e.g. report.md)")
    parser.add_argument("output_dir", nargs="?", default=None, help="Output directory (defaults to markdown file's directory)")
    parser.add_argument("--base-name", default=None, help="Output base filename without extension")
    parser.add_argument("--sample", default=None, help="Sample name to display in the header banner")
    parser.add_argument("--title", default=None, help="Custom report title")
    args = parser.parse_args()

    md_path = Path(args.markdown_file).resolve()
    if not md_path.is_file():
        print(f"Error: Input file not found: {md_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output_dir).resolve() if args.output_dir else md_path.parent
    base = args.base_name or md_path.stem

    if md_path.suffix.lower() == ".json":
        deliverables = render_reports(md_path, out_dir, log_fn=print)
    else:
        text = md_path.read_text(encoding="utf-8", errors="replace")
        sample_name = args.sample or args.title
        meta = {}
        if sample_name:
            meta["sample"] = {"filename": sample_name}
            meta["category"] = "Malware Analysis Report"
            meta["badges"] = ["Binary Lab Deliverables"]
        if args.title:
            meta["title"] = args.title

        deliverables = render_markdown_deliverables(text, out_dir, model=meta, base_name=base, log_fn=print)

    print("\nSuccessfully rendered deliverables:")
    for key, path in deliverables.items():
        print(f"  - {key.upper()}: {path}")
