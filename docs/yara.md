# YARA

The YARA section has three tools: a rule explorer for the rule corpus, a sample scanner for running rules against files, and a rule workbench for writing, checking and testing a rule.

Sidebar (under Threat Knowledge): **Rule Explorer** (`yara-explorer`), **Sample Scanner** (`yara-scanner`), **Rule Workbench** (`yara-workbench`).

Rules live in `backend/data/yara-rules/`. Deleted rules are tracked in `backend/data/yara_deleted_rules.json` so they are not restored by a sync.

## Rule Explorer

Browse and manage the rule corpus.

- **All Rules**, **Valid**, **Invalid**: filter by whether a rule compiles.
- **.\* Regex**: switch the search from plain text to a regular expression.
- **Select All** and **Clear All** select rules in bulk.
- **Create Rule** opens the workbench with a new rule.

Rules are read with `/api/yara/rules/search` and `/api/yara/rule`. Save or delete with `/api/yara/rule/save` and `/api/yara/rule/delete`. Corpus status and repositories are at `/api/yara/status` and `/api/yara/repos`.

## Sample Scanner

Scan files with the rules you select.

1. Open **Sample Scanner**.
2. Click **Browse Sample File** to pick a file, or drop one in. **Replace** swaps the file; **Clear** removes it.
3. Select rules in the list (**Select All** / **Clear All** to reset).
4. Click **Start YARA Scan**. Results are returned with each match and its strings (`POST /api/yara/scan`).

Scans run on the MANTIS server. Scan only files you are authorised to handle.

## Rule Workbench

Write, explain, check and test one rule.

- **Open Rule** loads an existing rule. **Save .yar** writes it to the corpus (`/api/yara/workbench/save`).
- **Check Syntax** compiles the rule (`/api/yara/validate`). **Beautify** formats it.
- **Pick Local File** or **Pick Local Folder** chooses test targets from your machine. The folder is used as a corpus test (`/api/yara/workbench/test-path`, `/api/yara/corpus/test`).
- **Execute YARA Scan** runs the rule against the targets. **Stop Scan** cancels a running scan.
- Results are shown under **Detections**, **Undetected**, **String Matches** and **Summary**. **Copy MD5s** copies the hashes of matched files. **Clear Results** resets the view.
- The AI panel offers **Explain Rule Logic**, **Diagnose Syntax Error** and **AI Auto-Fix & Optimize**. The auto-fix only changes the rule when it compiles; review the diff before you save.

### Tutorial: write and test a rule

1. Open **Rule Workbench** and paste the rule, or click **Open Rule** to start from one in the corpus.
2. Click **Check Syntax**. If it fails, click **Diagnose Syntax Error** for an explanation.
3. Click **Pick Local Folder** and choose a folder of known samples (benign and malicious) for the test.
4. Click **Execute YARA Scan**. Check **Detections** for expected matches and **Undetected** for misses.
5. Read **String Matches** to confirm the rule fires on the intended strings and not on common library code. Tighten the condition if it fires on too much.
6. Click **Save .yar** to store the rule. **Copy MD5s** gives the list of matched hashes for your notes.

### Tutorial: scan a suspicious file

1. Open **Sample Scanner**, click **Browse Sample File**, and choose the file.
2. Select the rules for the family you suspect (or **Select All**).
3. Click **Start YARA Scan** and read the matches. Add confirmed hashes to [IOC Search](ioc-search.md).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Rule shows as invalid | Click **Check Syntax** or **Diagnose Syntax Error**. |
| Scan finishes with no results | Check the rule is selected in the list and the file is readable. |
| Corpus is empty | Check `backend/data/yara-rules/` exists and has `.yar` or `.yara` files. The startup build can be turned on with `MANTIS_YARA_STARTUP_BUILD` (see [Getting Started](getting-started.md)). |
| Auto-fix changed a rule's meaning | Revert from the diff and fix by hand. |

## API reference

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/yara/status` | GET | Corpus status. |
| `/api/yara/rules/search`, `/api/yara/rule` | GET | Search and read rules. |
| `/api/yara/rule/save`, `/api/yara/rule/delete` | POST | Save or delete a rule. |
| `/api/yara/validate` | POST | Compile-check a rule. |
| `/api/yara/scan` | POST | Scan a file. |
| `/api/yara/workbench/save`, `/workbench/test-upload`, `/workbench/test-path` | POST | Workbench save and tests. |
| `/api/yara/corpus/test`, `/api/yara/corpus/dirs` | GET, POST | Corpus test and folders. |
| `/api/ai/yara/explain`, `/analyze-error`, `/suggest-fix`, `/auto-fix`, `/analyze-test` | POST | AI assistance. |
