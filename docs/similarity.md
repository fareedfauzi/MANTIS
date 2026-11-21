# Similarity

Similarity answers one question: *have I analysed a program that is structurally related to this one?* You group reference samples into a **family** (a malware family, a builder, a set of tools from one campaign), and every new sample is compared against those families.

Sidebar: **Similarity**. Sub-tabs: **Overview**, **Families**, **Compare**.

Data is stored in `backend/data/sample_similarity.db`. Uploaded samples are analysed and then deleted; only the extracted features are kept.

## Families

A family is a named group of reference samples.

- Adding samples analyses each one in the background, so the page stays usable while a large binary is digested.
- The family card shows how many samples it holds and how ready its profile is.
- A sample can be removed from a family without deleting the family.

Profile readiness matters, because it decides how much the score can claim:

| Samples in family | Profile state | What the score can say |
| --- | --- | --- |
| 0 | `EMPTY` | Nothing. Add a sample. |
| 1 | `SINGLE` | At most **WEAK**. One sample cannot tell family code from shared code. |
| 2 | `PROVISIONAL` | At most **LIKELY**. |
| 3-9 | `DEVELOPING` | Up to **STRONG**, once library filtering can see what is common. |
| 10+ | `ESTABLISHED` | Up to **STRONG**. |

## Compare Sample

1. Open **Compare Sample** and upload the sample.
2. The analysis runs in the background; large Go and Mach-O files take about a minute.
3. Read the label, then the features that produced it. Expand a feature to see the exact items that matched.

Labels are bands over the evidence score. They are deliberately conservative: one strong feature is never enough, and a family with a single sample cannot produce a confident call.

| Label | Evidence | Meaning |
| --- | --- | --- |
| **STRONG** | 70+ | Several independent signals agree, and the family has enough samples to have filtered out library code. |
| **LIKELY** | 50+ | Clear structural overlap. Treat as a lead, then confirm by hand. |
| **WEAK** | 12+ | Some overlap, possibly a shared runtime, a shared language, or the same project. Not a conclusion. |
| **NO MATCH** | below 12 | Nothing that ties this sample to that family. |
| **INSUFFICIENT EVIDENCE** | - | Fewer than two features could be analysed, so no family is called. |

If a file is already in a family, the comparison says **Already a member** and names it.

### What is compared

Every feature is scored on its own and then combined with fixed weights that always add up to 100, so a missing feature counts as zero instead of being rescaled into a high score.

| Feature | Weight | What it measures |
| --- | --- | --- |
| Exact function matches | 14 | Function fingerprints shared with the family. |
| Strings | 12 | Strings weighted by rarity across your families. |
| Fuzzy code similarity | 11 | Similar-but-not-identical function code. |
| Version metadata | 11 | Company, product, description, version and other build metadata. |
| TLSH | 10 | Fuzzy whole-payload hash distance. |
| Imports | 7 | Imported libraries and APIs. |
| Go symbols | 8 | Package and function names from the Go build. |
| Python modules | 8 | Third-party modules bundled by PyInstaller. |
| Python symbols | 6 | Function and class names in the program's own code objects. |
| C++/Rust symbols | 5 | Demangled function names. |
| FLOSS strings | 4 | Obfuscated or decoded strings. |
| API behaviour | 2 | Categories of imported API behaviour. |
| VirusTotal | 2 | External corroboration, never a local signal. |

VirusTotal only ever contributes two points and never counts toward the "two features must be analysed" rule, because it is external evidence about a hash, not an analysis of the file.

### Formats and what is used for each

| File | Features used |
| --- | --- |
| PE (native) | Functions, strings, imports, metadata, TLSH, API behaviour |
| PE (.NET) | Managed IL bodies and metadata |
| ELF | Functions, strings, imports, TLSH |
| Mach-O | Functions, strings, imports, TLSH |
| Go | Go symbols plus exact function boundaries from GoReSym |
| PyInstaller one-file | The program's own code objects: Python symbols, literals, module list |

For a PyInstaller bundle the launcher and the embedded Python standard library are **not** fingerprinted. Otherwise every bundle ever built with the same PyInstaller version would match every other one.

## Reading a WEAK result

A WEAK result on a family with fewer than four samples carries an explicit warning in the result. With so few samples, code that every program of that kind shares - the C runtime, the Go runtime, a bundled interpreter - cannot be recognised as shared, so it counts as family evidence. Add more distinct families and the same comparison gets stricter.

Keep that in mind before treating a WEAK result as an attribution.

The technical reason: an item is only recognised as library code once it appears in several distinct families (four). With a single family in the library there is nothing to compare it against, so the runtime stays in the family's profile and looks like family code.

The warning is not a retraction of the result; it says the score cannot yet separate family code from shared code.

## Overview

**Overview** shows the local library at a glance: how many families and samples exist, which families are still too thin to be conclusive, and recent comparisons. Start here after adding your first reference samples.

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/similarity/dashboard` | GET | Counts and the most recent activity. |
| `/api/similarity/families` | GET, POST | List or create a family. |
| `/api/similarity/families/{id}` | GET, PUT, DELETE | Read, rename or delete a family. |
| `/api/similarity/families/{id}/samples` | POST | Add reference samples; returns a job id. |
| `/api/similarity/families/{id}/samples/{sample_id}` | DELETE | Remove one sample from a family. |
| `/api/similarity/compare` | POST | Compare an uploaded sample; returns a job id. |
| `/api/similarity/jobs/{job_id}` | GET | Progress and result of an ingest or comparison. |
| `/api/similarity/comparisons` | GET | Recent comparisons. |
| `/api/similarity/comparisons/{id}` | GET | One stored comparison. |
| `/api/similarity/vt/status` | GET | Whether a VirusTotal key is configured. |

Because analysis runs in the background, both POST routes answer immediately with a job id. Poll the job until its status is `done` or `failed`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Everything is **NO MATCH** | The family has few samples, or the sample really is unrelated. Compare two known-related samples first to see what a match looks like. |
| **INSUFFICIENT EVIDENCE** | The file is packed or too small to analyse. Unpack it first. |
| A file was skipped on ingest | Its type was not recognised, so there was nothing to compare. The job reports that file as `skipped` with the reason. |
| A Go binary takes a minute | Expected. Go extraction reads tens of thousands of functions; it runs in the background. |
| VirusTotal is unavailable | No key is configured. Add one in Settings. |
