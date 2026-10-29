# -*- coding: utf-8 -*-
"""Build a navigable evidence-edge graph from API and sequence semantics."""
import idaapi
import ida_kernwin

from genesect.api_sequence_explorer import scan_api_sequences
from genesect.semantic_evidence import collect_api_calls
from genesect.ui.semantic_explorer import SemanticExplorerForm


_explorer = None


def build_evidence_edges():
    edges = []
    calls_by_function = collect_api_calls()
    for _func_ea, calls in calls_by_function.items():
        for call in calls:
            knowledge = call["knowledge"]
            taxonomy = knowledge.get("taxonomy") or {}
            if knowledge.get("ignored") or not taxonomy:
                continue
            source = call["function"]
            api = call["api"]
            category = taxonomy.get("category") or "uncategorized"
            edges.append({
                "ea": call["site"], "source": source, "relation": "calls", "target": api,
                "kind": "API", "confidence": "DIRECT", "address": "0x%X" % call["site"],
                "details": "0x%X: %s directly calls %s\nTaxonomy: %s\nSeverity: %s" % (call["site"], source, api, category, taxonomy.get("severity") or "unknown"),
            })
            edges.append({
                "ea": call["site"], "source": api, "relation": "classified as", "target": category,
                "kind": "Taxonomy", "confidence": "KNOWLEDGE", "address": "0x%X" % call["site"],
                "details": "%s is classified as %s by the bundled malware API taxonomy.\nEvidence site: 0x%X" % (api, category, call["site"]),
            })
        if ida_kernwin.user_cancelled():
            return edges
    for sequence in scan_api_sequences(calls_by_function):
        edges.append({
            "ea": sequence["ea"], "source": sequence["function"], "relation": "exhibits", "target": sequence["sequence"],
            "kind": "Sequence", "confidence": sequence["severity"], "address": sequence["address"], "details": sequence["details"],
        })
    unique = {(row["source"], row["relation"], row["target"], row["ea"]): row for row in edges}
    return sorted(unique.values(), key=lambda row: (row["source"].casefold(), row["ea"], row["kind"]))


class EvidenceGraph(SemanticExplorerForm):
    title = "API Classification Explorer"
    subtitle = "Classify and correlate API calls to identify malware behaviors and explore evidence"
    columns = (("source", "Source"), ("relation", "Relation"), ("target", "Target"), ("kind", "Evidence type"), ("confidence", "Confidence"), ("address", "Address"))
    wait_message = "Building the semantic evidence graph..."
    export_name = "api_classification.csv"

    def scan(self):
        return build_evidence_edges()

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def explore_api_classification():
    """Return categorized API calls for Malware Analysis Assist."""
    results = []
    calls_by_function = collect_api_calls()
    for _func_ea, calls in calls_by_function.items():
        for call in calls:
            knowledge = call.get("knowledge") or {}
            taxonomy = knowledge.get("taxonomy") or {}
            if knowledge.get("ignored") or not taxonomy:
                continue
            category = taxonomy.get("category") or "Uncategorized"
            severity = str(taxonomy.get("severity") or "LOW").upper()
            results.append({
                "ea": call["site"],
                "function": call["function"],
                "api": call["api"],
                "category": category,
                "severity": severity,
                "confidence": "high",
                "evidence": "%s directly calls %s" % (call["function"], call["api"]),
                "detail": "%s is classified as %s (%s severity)" % (call["api"], category, severity),
            })
        if ida_kernwin.user_cancelled():
            break
    return results


def show_evidence_graph():
    from genesect.malware_triage import show_malware_analysis_assist
    from genesect.malware_triage_model import DETECTOR_API_CLASSIFICATION
    show_malware_analysis_assist(DETECTOR_API_CLASSIFICATION)


class EvidenceGraphHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_evidence_graph()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
