# SEDG Agent Guidance

## Project and Risk Model

SEDG is a Python 3.10 project for tracking security issues in version control.
It reads, edits, queries, and reports CVE records stored in the RFC5322-based
format documented in `README.md`. Records can contain private or embargoed
security information. A defect can corrupt tracker data, expose sensitive
content, or produce incorrect security reports.

Work from the repository root. Preserve the documented file format, command
behavior, and unrelated user changes. Keep changes narrow.

## Task Scope and Autonomy

* For review, explanation, diagnosis, or planning, inspect and report without
  modifying files.
* For change, build, or fix requests, make in-scope local changes and run
  relevant non-destructive checks without asking first.
* Make routine decisions independently. Ask only when materially different
  interpretations would produce different outcomes.
* Require explicit authorization for root commands, destructive actions,
  external writes, access to real private CVE data, production dependencies,
  or material scope expansion.
* Do not contact GitHub, Google Artifact Registry, Quay, Docker DSO, InfluxDB,
  or another external service unless the task requires it and the user
  authorizes the access.
* Deliver the requested scope completely without silently narrowing, widening,
  or transforming it.

## Agent Environment

### Virtual Environment

Use `.venv.ai` and activate it in each new shell:

```bash
source ./.venv.ai/bin/activate
```

If it is absent or unusable, delete and recreate only `.venv.ai`, then run
`make VENV=.venv.ai install-venv-dev`. Do not delete or recreate any other
virtual environment. Verify the environment with `cve-report --help`.

### Temporary Files

* Create temporary files with `mktemp /tmp/ai-agent-XXXXXX` and directories
  with `mktemp -d /tmp/ai-agent-XXXXXX`.
* Clean up only the exact temporary paths created for the task.

## Security and Data Integrity

Treat CLI arguments, environment variables, configuration, CVE content,
filesystem metadata, command output, and API responses as untrusted.

### CVE Records

* Validate external values before use and again at each trust boundary. Reject
  malformed or ambiguous input instead of silently repairing it.
* Preserve the RFC5322 syntax, field semantics, folding, ordering requirements,
  and ASCII constraints described in `README.md`. Do not silently convert the
  format to RFC6532 or another format.
* Preserve unknown data when the format requires round-trip compatibility.
  Do not invent, discard, reorder, or normalize fields without a documented
  reason.
* Use synthetic records for tests. Do not read, copy, print, or include real
  private or embargoed records in tests, logs, fixtures, commits, or responses.
* Show only the minimum sensitive context needed to diagnose a problem.

### Commands, Files, and External Data

* Pass argument lists to subprocess APIs and keep `shell=False`. Do not use
  `shell=True`, `os.system`, `eval`, or `exec`.
* Validate user-derived command arguments, paths, identifiers, URLs, and
  external response fields before use.
* Prevent path traversal and unsafe link handling. Use temporary directories
  for tests and remove only the exact resources created by the test.
* Use safe YAML loading and validate the resulting structure. Do not use
  `pickle` or dynamically import code selected by external input.
* Do not hardcode or expose credentials, tokens, private record content, or
  unnecessary host details. Keep secrets out of command lines and logs.
* Preserve existing error handling and fail closed when malformed data could
  affect confidentiality or record integrity.

## Code Conventions

* Follow Black formatting and the existing project style.
* Production source outside `tests/` must contain ASCII only. Tests may use
  non-ASCII text only when required to test that behavior.
* Keep code compatible with Python 3.10.
* Keep functions focused. Prefer existing helpers and public interfaces over
  duplicated logic.
* Avoid unrelated formatting, typing, dependency, or refactoring churn.
* Comments must explain non-obvious reasons or security assumptions, not
  restate the code.

### Function Names

In production files:

* Functions beginning with `main_` use snake_case, such as `main_foo_bar`.
* All other functions use lower camel case, such as `fooBar`.
* File-private functions begin with `_`, such as `_validateInput`.

In `tests/test_*.py`:

* A test for a function starts with `test_` followed by the exact function
  name: `test_main_foo_bar`, `test_fooBar`, or `test__validateInput`.
* Additional descriptors use snake_case, such as
  `test_fooBar_with_invalid_input`.
* General test names use snake_case. Test helpers use snake_case with a leading
  `_`.

## Test Design

Unit tests must be deterministic and must not require real credentials,
private CVE data, or live services.

* Exercise public behavior with real data structures, synthetic user input,
  temporary files, and realistic configuration where practical.
* Mock external processes, command discovery, network requests, and other
  side-effecting boundaries. Mock `open` only for focused I/O failures and
  `print` only to verify console output.
* Do not mock internal helpers unless isolation is otherwise impractical.
  Refactor tightly coupled code when that improves testability.
* Use context-managed temporary directories for isolated cases. Where shared
  setup is useful, follow the established `self.tmpdir` pattern and clean it
  with `cvelib.common.recursive_rm`.
* Reuse helper methods, data factories, context managers, and shared test
  utilities for repeated setup and complex records.
* Assert exact output and error behavior. Cover every practical branch,
  including success and error paths, empty or `None` values, malformed data,
  boundaries, and external-service errors.
* Add a regression test for each bug fix. Aim for 100 percent coverage where
  achievable. If code is unreachable, document why or refactor it; do not add
  low-value tests only to raise coverage.

## Validation

With `.venv.ai` active, run the smallest validation sequence that covers the
change:

1. Focused test:
   `python3 -m unittest tests.test_cve.TestCve.test_bar`
2. Updated test module: `python3 -m unittest tests.test_cve`
3. Full suite: `make test`
4. Coverage: `make coverage`, then `make coverage-report`
5. Type analysis for changed Python: `pyright`
6. Style: `make style-check`; use `make style-fix` only to fix relevant
   formatting failures
7. Syntax and lint checks: `make syntax-check`

Advance through the sequence only after the prior step passes. After a failure
or material correction, restart at the focused test. Run `make syntax-check`
once near completion. Run `git diff --check` for every change. For
documentation-only changes, also run ASCII validation.

Keep tool output small. Redirect verbose tests, coverage, or other commands
likely to produce long output to temporary files, then inspect exit status and
only targeted `tail`, `wc`, `rg`, or small `sed` excerpts. Report checks that
fail or cannot run. Do not weaken checks to obtain a passing result.

## Communication

* Use ASD-STE100 Simplified Technical English, Issue 9, as the reference
  standard for all authored prose, including agent messages, review findings,
  summaries, issue content, and pull request content. In practice: short
  sentences (approximately 20 words or fewer), active voice, one meaning per
  word, no idioms, no metaphors or other figurative language. Use a necessary
  technical term even when the STE dictionary does not contain it.
* Use a neutral, direct tone. Lead with findings and omit generic praise,
  reassurance, and filler.
* Do not send interim progress updates. Report only material findings and
  changes of scope.
* Make each claim proportional to its evidence. Label inference and uncertainty.
* Match the response length to the findings. Preserve evidence, caveats, and
  gaps; omit repeated summaries. Keep code excerpts short.
