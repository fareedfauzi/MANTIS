# -*- coding: utf-8 -*-
"""Detect ordered, corroborated API behavior sequences."""
import idaapi
import ida_kernwin

from genesect import api_taxonomy
from genesect.semantic_evidence import collect_api_calls, format_call
from genesect.ui.semantic_explorer import SemanticExplorerForm


_explorer = None
_SEQUENCES = (
    ("Remote-thread injection", (("openprocess",), ("virtualallocex", "ntallocatevirtualmemory"), ("writeprocessmemory", "ntwritevirtualmemory"), ("createremotethread", "ntcreatethreadex", "rtlcreateuserthread")), "HIGH"),
    ("Process hollowing", (("createprocessa", "createprocessw", "ntcreateuserprocess"), ("ntunmapviewofsection", "zwunmapviewofsection"), ("writeprocessmemory", "ntwritevirtualmemory"), ("setthreadcontext", "ntsetcontextthread"), ("resumethread", "ntresumethread")), "HIGH"),
    ("Runtime API resolution", (("loadlibrarya", "loadlibraryw", "ldrloaddll", "dlopen"), ("getprocaddress", "ldrgetprocedureaddress", "dlsym")), "MEDIUM"),
    ("Registry persistence", (("regcreatekeyexa", "regcreatekeyexw", "regopenkeyexa", "regopenkeyexw"), ("regsetvalueexa", "regsetvalueexw")), "HIGH"),
    ("Network receive and execution", (("recv", "wsarecv", "internetreadfile", "winhttpreaddata"), ("virtualprotect", "ntprotectvirtualmemory", "mprotect")), "HIGH"),
)


def _ordered_matches(calls, stages):
    selected, cursor = [], -1
    for alternatives in stages:
        found = next((call for call in calls if call["site"] > cursor and call["api"].casefold() in alternatives), None)
        if not found:
            return []
        selected.append(found)
        cursor = found["site"]
    return selected


def scan_api_sequences(calls_by_function=None):
    rows = []
    source = collect_api_calls() if calls_by_function is None else calls_by_function
    for func_ea, calls in source.items():
        for name, stages, severity in _SEQUENCES:
            selected = _ordered_matches(calls, stages)
            if not selected:
                continue
            rows.append({
                "ea": selected[0]["site"], "address": "0x%X" % selected[0]["site"],
                "function": selected[0]["function"], "sequence": name,
                "severity": severity, "steps": len(selected),
                "details": "%s\n\nOrdered evidence:\n%s" % (name, "\n".join(format_call(call) for call in selected)),
            })
        hits = {}
        for call in calls:
            taxonomy = call["knowledge"].get("taxonomy")
            if taxonomy and not call["knowledge"].get("ignored"):
                hits.setdefault(taxonomy["category"], []).append(call["api"])
        for rule in api_taxonomy.evaluate_combination_rules(hits):
            evidence = [call for call in calls if (call["knowledge"].get("taxonomy") or {}).get("category") in hits]
            rows.append({
                "ea": calls[0]["site"], "address": "0x%X" % calls[0]["site"],
                "function": calls[0]["function"], "sequence": rule["name"],
                "severity": rule["severity"], "steps": len(evidence),
                "details": "%s\n\nTriggered taxonomy categories: %s\n\nAPI evidence:\n%s" % (
                    rule["description"], ", ".join(sorted(hits)), "\n".join(format_call(call) for call in evidence[:64])),
            })
        if ida_kernwin.user_cancelled():
            break
    unique = {(row["ea"], row["sequence"]): row for row in rows}
    return sorted(unique.values(), key=lambda row: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(row["severity"], 3), row["function"], row["ea"]))


class APISequenceExplorer(SemanticExplorerForm):
    title = "API Sequence Explorer"
    subtitle = "Ordered API behaviors and taxonomy combinations; isolated dual-use calls are omitted"
    columns = (("sequence", "Sequence"), ("severity", "Severity"), ("function", "Function"), ("address", "Address"), ("steps", "Steps"))
    wait_message = "Correlating ordered API behavior sequences..."
    export_name = "api_sequences.csv"

    def scan(self):
        return scan_api_sequences()

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_api_sequence_explorer():
    global _explorer
    if _explorer is None:
        _explorer = APISequenceExplorer()
    _explorer.Show("Genesect - API Sequence Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class APISequenceExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_api_sequence_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
