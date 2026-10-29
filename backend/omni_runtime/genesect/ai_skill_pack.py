# -*- coding: utf-8 -*-
"""Portable AI-agent skill pack for Genesect workspace exports."""

from __future__ import annotations

import os


def _win_path(path):
    if not path or not isinstance(path, str):
        return path
    if os.name != "nt":
        return path
    norm = os.path.normpath(os.path.abspath(path))
    if norm.startswith("\\\\?\\"):
        return norm
    if norm.startswith("\\\\"):
        return "\\\\?\\UNC\\" + norm[2:]
    return "\\\\?\\" + norm


def _ensure_dir(path):
    wpath = _win_path(path)
    if not os.path.isdir(wpath):
        os.makedirs(wpath, exist_ok=True)


def _write_text(path, text):
    parent = os.path.dirname(path)
    if parent:
        _ensure_dir(parent)
    with open(_win_path(path), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _binary_summary(metadata):
    return {
        "input_file": metadata.get("input_file", ""),
        "imagebase": metadata.get("imagebase", ""),
        "md5": metadata.get("md5", ""),
        "sha256": metadata.get("sha256", ""),
    }


def write_skill_pack(root, metadata):
    """Write generic agent instructions plus Codex/Claude/Cursor compatible skill files."""
    root = os.path.normpath(os.path.abspath(root))
    summary = _binary_summary(metadata)
    malware_skill_dir = os.path.join(root, "skills", "genesect-malware-re")
    router_skill_dir = os.path.join(root, "skills", "genesect-triage-router")
    _ensure_dir(malware_skill_dir)
    _ensure_dir(router_skill_dir)
    _write_text(os.path.join(root, "AGENTS.md"), _agents_md(summary))
    _write_text(os.path.join(root, "CODEX.md"), _agent_pointer("Codex"))
    _write_text(os.path.join(root, "CLAUDE.md"), _agent_pointer("Claude"))
    _write_text(os.path.join(root, "skills", "README.md"), _skills_readme())
    _write_text(os.path.join(router_skill_dir, "SKILL.md"), _triage_router_skill_md())
    _write_text(os.path.join(malware_skill_dir, "SKILL.md"), _malware_skill_md())
    _write_text(os.path.join(root, ".cursor", "rules", "genesect-malware-re.mdc"), _cursor_rule())


def _agent_pointer(agent_name):
    return """# Genesect Workspace Instructions for %s

Start with `skills/genesect-triage-router/SKILL.md` to route the investigation and define evidence gates.

Use `skills/genesect-malware-re/SKILL.md` as the primary malware reverse-engineering playbook for this exported workspace.

Start with `manifest.json`, `functions/index.tsv`, and `functions/callgraph.tsv`; then inspect only the function files, strings, imports, exports, and Genesect evidence needed for the current question.

Always report addresses and evidence. Separate confirmed facts from hypotheses.
""" % agent_name


def _skills_readme():
    return """# Genesect AI Skills

This folder contains portable agent instructions for malware analysis and reverse engineering. The skills are plain Markdown so they can be used by Codex, Claude, Cursor, Cline, and other local AI coding agents.

Available skills:

- `genesect-malware-re`: Malware-focused reverse-engineering workflow for Genesect AI Workspace exports and IDA Pro 9.3 IDAPython work.
- `genesect-triage-router`: Beginner-friendly routing, evidence collection, validation gates, and reproducible deliverable guidance for reverse-engineering cases.
"""


def _agents_md(summary):
    return """# Genesect AI Workspace

This folder is exported from IDA Pro by Genesect for local AI-assisted reverse engineering.

Use `skills/genesect-triage-router/SKILL.md` first to route the investigation, define the objective, and set evidence gates.

Use the skill at `skills/genesect-malware-re/SKILL.md` for malware-analysis workflow, evidence rules, and IDA Pro 9.3 scripting guidance.

## Layout

- `manifest.json`: database metadata and export counts.
- `run_analysis.md`: autonomous two-phase reverse-engineering and reporting prompt.
- `render_report.py`: self-contained Markdown-to-HTML/PDF report renderer used by the analysis prompt.
- `modules/`: categorized by behavior (e.g. `01_network_c2`, `02_crypto_encoding`, `03_evasion_injection`) containing `.c`, `.asm`, and `.brief.md` per function.
- `catalog/`: machine-readable summaries for triage, functions, types, globals, entrypoints, CFGs, variables, data objects, fixups, switches, pointer tables, analysis gaps, source mappings, imports, strings, and callgraphs.
- `headers/signatures.h` and `headers/local_types.h`: recovered function prototypes and Local Types.
- `functions/index.tsv`: function address, size, flags, callers, callees, and exported file paths.
- `functions/callgraph.tsv`: caller/callee edges.
- `functions/decompiled/`: Hex-Rays output when available.
- `functions/disassembly/`: IDA disassembly fallback for every exported function.
- `globals.tsv` and `catalog/globals.json`: global data with types, sizes, initial values, aliases, read/write references, and referencing functions.
- `xrefs.tsv`, `functions/cfg/`, and `functions/variables/`: exact typed references, basic-block graphs, stack frames, and Hex-Rays locals.
- `data/` plus `catalog/data_objects.json`: bounded raw payloads for exported global objects.
- `catalog/entrypoints.json`, `fixups.json`, `switches.json`, `pointer_tables.json`, `analysis_gaps.json`, and `source_map.json`: startup, indirect-flow, uncertainty, and debug/source evidence.
- `strings.tsv`, `imports.tsv`, `exports.tsv`, `segments.tsv`, `names.tsv`: searchable IDB context.
- `go_rust_user_code_map.csv`: Genesect Go/Rust classification evidence when collection succeeds.
- `virtual_classes.txt`: recovered vtables/classes and evidence when collection succeeds.

## Ground Rules

- Prefer concrete evidence from addresses, xrefs, strings, imports, and recovered types.
- Treat Go/Rust package, crate, runtime, and vtable classifications as heuristics unless corroborated by code.
- When proposing renames, comments, or follow-up scripts, include the address and the reason.
- Do not assume exported decompilation is perfect; compare with disassembly for suspicious control flow.
- Keep malware-analysis output defensive: identify behavior, IOCs, config, protocols, persistence, evasion, and impact.

## Binary

- Input: `%s`
- Image base: `%s`
- MD5: `%s`
- SHA256: `%s`
""" % (
        summary["input_file"],
        summary["imagebase"],
        summary["md5"],
        summary["sha256"],
    )


def _cursor_rule():
    return """---
description: Genesect malware reverse-engineering workspace analysis
globs:
  - "**/manifest.json"
  - "**/functions/**/*.c"
  - "**/functions/**/*.asm"
  - "**/*.tsv"
alwaysApply: false
---

Use `skills/genesect-triage-router/SKILL.md` first, then `skills/genesect-malware-re/SKILL.md` as the analysis playbook. Cite function addresses, file paths, imports, strings, callgraph edges, and Genesect evidence. Keep conclusions evidence-backed and defensive.
"""


def _triage_router_skill_md():
    return """---
name: genesect-triage-router
description: Use at the start of a Genesect AI Workspace investigation to identify the target, route the task, preserve evidence, define confidence gates, validate outputs, and produce reproducible reverse-engineering deliverables.
---

# Genesect Triage Router

## Purpose

Use this skill before deep analysis. Its job is to prevent the agent from guessing, over-reading a single string, or jumping straight into a complex tool. It turns a vague reverse-engineering request into a small, evidence-backed route.

## Four Startup Questions

Answer these from the workspace when possible. If an answer is missing, state the smallest artifact needed.

1. What are we analyzing: PE, ELF, Mach-O, firmware, APK/SO/DEX, Go/Rust binary, shellcode, dump, PCAP, or only exported IDA files?
2. What action matters: entrypoint triage, config extraction, C2/protocol recovery, unpacking, deobfuscation, symbol recovery, vtable/class recovery, string recovery, patch planning, or report writing?
3. What material exists: `manifest.json`, function export, strings, imports, callgraph, Go/Rust map, virtual classes, logs, PCAP, memory dump, dynamic trace, or only a description?
4. What result do we need: plain-English summary, IOC table, key functions, rename plan, IDA script, YARA/Sigma seed, deobfuscation plan, patch plan, or reproducible report?

## Routing Table

- Malware behavior, IOCs, C2, persistence, injection, anti-analysis: use `genesect-malware-re`.
- Go/Rust runtime noise or package/crate ownership: use `go_rust_user_code_map.csv` before reading many function files.
- C++ virtual dispatch, recovered classes, constructors, destructors: use `virtual_classes.txt` before proposing class names.
- Unknown stripped native binary: start with imports, strings, exports, names, function sizes, and callgraph hubs.
- Suspected unpacking or dump analysis: validate headers, sections/segments, mappings, imports/relocations, entrypoint, and consumer-tool loading before trusting the dump.
- Patch or hook request: require baseline behavior, changed behavior, repeat run, rollback plan, and exact address-level evidence.

## Evidence Collection Rules

- Preserve raw artifacts and record hashes before modifying, decoding, dumping, or patching anything.
- Separate four buckets: static facts, runtime observations, inferences, and unresolved questions.
- Correlate at least two signals when possible: code, xrefs, strings, imports, globals, memory maps, stack/register trace, file/registry activity, traffic, or output.
- A string alone is not a call chain.
- A decompiler statement alone is not proof when disassembly disagrees.
- A dump is not valid until structure, mappings, imports/relocations, symbols, and at least one consumer tool agree.
- A patch, hook, or workaround is not stable until clean baseline, cold start, warm start, and repeated execution are compared.

## Confidence Levels

- High: multiple independent artifacts agree and the relevant code path is reachable.
- Medium: strong static evidence exists but runtime/path validation is missing.
- Low: one signal exists, or the result depends on uncertain decompilation, guessed types, or unresolved indirect calls.
- Unknown: not enough material; name the smallest next artifact required.

## Minimal Workspace Case Notes

When the task is non-trivial, maintain this structure in the response or generated report:

```text
case/
  objective
  artifacts and hashes
  timeline
  hypotheses
  evidence table
  route taken
  results
  limitations
  next actions
```

Do not create extra files unless asked. The exported workspace already contains the evidence; use reports only when they help preserve decisions.

## Deliverable Template

1. Beginner summary: what this target appears to do and why.
2. Route: which skill/files were used and why.
3. Evidence table: address/file, artifact, observation, confidence.
4. Technical chain: entry -> loader/dispatcher -> logic -> output.
5. Reproducibility: commands, scripts, offsets, hashes, tool assumptions.
6. Limitations: what is not proven yet.
7. Next action: smallest concrete artifact or analysis step.
"""


def _malware_skill_md():
    return """---
name: genesect-malware-re
description: Use when analyzing Genesect AI Workspace exports, malware samples, stripped binaries, decompiled functions, IDA Pro 9.3 IDAPython tasks, Go/Rust user-code maps, or recovered vtables/classes.
---

# Genesect Malware Reverse Engineering

## When To Use

Use this skill for defensive malware analysis, binary reverse engineering, triage of Genesect AI Workspace exports, and IDA Pro 9.3 scripting. It is designed for Codex, Claude, Cursor, Cline, and other local AI coding agents that can read files.

Do not use this skill to produce deployable malware, persistence implants, credential theft logic, evasion payloads, or exploit chains. It is fine to identify, explain, detect, emulate, or safely instrument suspicious behavior for analysis.

## Reading Order

1. Read `manifest.json` for architecture, hashes, image base, and export counts.
2. Read `functions/index.tsv` to find names, sizes, flags, callers, callees, and file paths.
3. Read `functions/callgraph.tsv` to understand reachability and dispatcher relationships.
4. Search `strings.tsv`, `imports.tsv`, `exports.tsv`, and `names.tsv` for capability leads.
5. Use `go_rust_user_code_map.csv` to separate user, dependency, stdlib, and runtime code when present.
6. Use `virtual_classes.txt` to identify C++ vtables, methods, constructors, destructors, and RTTI evidence when present.
7. Open decompiled files first, then compare with matching disassembly when control flow, pointer arithmetic, or indirect calls look suspicious.

## Evidence Rules

- Always cite addresses such as `0x140012340`.
- Distinguish confirmed facts from hypotheses.
- Tie every behavioral claim to at least one concrete artifact: function, import, string, xref, callgraph edge, constant, global, vtable, or decompiled statement.
- Prefer small evidence sets over broad summaries. A good answer says where the claim came from.
- If decompilation and disassembly disagree, trust disassembly and explain the uncertainty.
- For renames, include the old name, proposed name, address, and reason.

## Malware Triage Workflow

1. Entry points: inspect `exports.tsv`, known entry functions, TLS callbacks, constructors, thread starts, and high-centrality dispatchers.
2. Capability map: group imports and callees into networking, crypto, file system, registry, process/thread, injection, service, COM, anti-analysis, and persistence.
3. Configuration: search strings and global references for domains, IPs, URIs, mutexes, registry keys, user-agent strings, campaign IDs, magic constants, encodings, and encrypted blobs.
4. Control flow: identify dispatch loops, command handlers, callback tables, virtual dispatch, indirect calls, and state machines.
5. Data flow: trace config into network, crypto, process creation, file writes, registry writes, or callback registration.
6. Anti-analysis: look for debugger checks, VM/sandbox artifacts, timing checks, exception tricks, API hashing, delayed imports, and opaque predicates.
7. Output: produce an evidence-backed report with behavior, IOCs, key functions, confidence, unresolved questions, and recommended next analysis steps.

## IOC Extraction Rules

- Do not invent indicators. Extract only values present in exported evidence, analyst notes, logs, strings, decompilation, disassembly, or recovered config.
- Defang network and email indicators in reports by default: `hxxp://`, `[.]`, `[@]`.
- Keep both forms when useful: original-as-seen and defanged-for-sharing.
- Every IOC needs source, evidence snippet, confidence, and context.
- Label ambiguous values as candidate, contextual, incomplete, or low confidence.
- Do not resolve domains, browse URLs, or test live infrastructure from this workspace unless the analyst explicitly authorizes a separate enrichment step.

IOC table columns:

- Type
- Indicator
- Defanged
- Confidence
- Context
- Source artifact
- Evidence

## Packing And Unpacking Rules

- Static-first: use sections, imports, entropy, strings, overlays, loader stubs, unusual entrypoints, and Genesect evidence before proposing runtime unpacking.
- Known offline unpackers may be suggested only when evidence supports the packer family.
- Dynamic unpacking requires an isolated VM or sandbox, snapshot, explicit analyst approval, monitoring plan, and rollback.
- Never claim an unpacked artifact exists unless it was produced and hashed.
- Validate unpacked or dumped artifacts with headers, sections/segments, imports/relocations, strings increase, consumer-tool loading, and behavior parity where possible.

## Detection And Report Rules

- YARA seeds should come from stable code bytes, strings, config constants, imports, or family-specific markers; avoid volatile addresses and single generic strings.
- Sigma or hunting logic should cite behavior and telemetry source assumptions.
- Reports must separate observed facts, inferred behavior, and unresolved hypotheses.
- Include hashes when known, but do not treat a hash alone as behavioral analysis.
- For ATT&CK mapping, include technique IDs only when the behavior is actually evidenced.

## Function Analysis Template

For each important function, answer:

- Address and current name.
- Likely role in one sentence.
- Inputs, outputs, and important globals.
- Key callees and callers.
- Notable strings, imports, constants, and structs.
- Malware relevance: config, C2, unpacking, persistence, injection, evasion, crypto, or utility.
- Rename/comment proposal if useful.
- Confidence and why.

## Go And Rust Notes

- Treat runtime and standard-library code as boundary context unless it directly explains program behavior.
- Prioritize rows marked `User` or `ThirdParty` in `go_rust_user_code_map.csv`.
- For Go, package paths often identify first-party code, vendored dependencies, and command handlers.
- For Rust, demangled crate paths, panic strings, `lang_start_internal` flows, and source paths often reveal entry logic and error-handling paths.
- Do not mistake Rust `drop_in_place`, allocator, panic, or formatting routines for user malware behavior without caller evidence.

## C++ And VTable Notes

- Use `virtual_classes.txt` as a heuristic class map, not as final type truth.
- Validate vtable methods by xrefs, constructor writes, RTTI, and callsites.
- Watch for virtual dispatch used as command handlers, protocol handlers, parsers, unpacking stages, or plugin architectures.
- When proposing class names, base them on method behavior and stable evidence, not only the table name.

## IDA Pro 9.3 IDAPython Guidance

Use IDA Pro 9.3 compatible Python 3 APIs. Prefer structured modules over IDC-style shortcuts when possible:

- Functions: `ida_funcs`, `idautils.Functions`, `idautils.FuncItems`.
- Names: `ida_name`, `idc.get_name`, `ida_funcs.get_func_name`.
- Xrefs: `idautils.XrefsFrom`, `idautils.XrefsTo`.
- Bytes and data: `ida_bytes`, `ida_segment`, `ida_nalt`.
- UI: `ida_kernwin`, `idaapi.action_handler_t`, `idaapi.action_desc_t`.
- Decompiler: `ida_hexrays.init_hexrays_plugin()`, `ida_hexrays.decompile(ea)`.
- Constants: use `idaapi.BADADDR` and module constants where available.

IDA scripting rules:

- Never perform mass renames, comments, type changes, or patches without an explicit analyst confirmation step.
- For scripts that modify the IDB, support dry-run mode and print a concise change plan.
- Catch decompiler failures per function and keep processing.
- Keep long operations cancelable with `ida_kernwin.show_wait_box()` or a Qt progress dialog.
- Use UTF-8 output files and stable address-prefixed filenames.

## Report Format

When asked for a summary, prefer:

1. Executive conclusion.
2. Key functions with addresses.
3. Capabilities and evidence.
4. IOCs and configuration.
5. Anti-analysis or obfuscation.
6. Confidence and gaps.
7. Next concrete reversing steps.
"""
