# Working with any coding agent

This repository uses Python commands, JSON files and ordinary filesystem logs.
It needs no particular agent, desktop client, MCP server or vendor account.
Read README.md (English) or README.zh-CN.md, then docs/WORKFLOW.md or its Chinese
counterpart. Use the source to establish exact contracts.

## Before touching a camera

1. Run `python a7cr.py doctor` and `python a7cr.py project status --project PATH`.
   These commands do not enumerate or authenticate USB.
2. Confirm the owner's model and displayed firmware. The adapter targets A7CR
   2.01, not A7C II or other firmware. Version input is a declaration; full source
   checks and actual body binding still run later.
3. Use a fresh private project. Firmware, calibration, body-bound manifests,
   derived tables, photos and logs remain local. Never copy another body's job.
4. Finish offline preparation, placement/loading checks, actual native-worker
   emulation, host tests, inverse checks and hash-bound receipts first. Do not
   replace missing evidence with `passed: true` or edit a phase to advance it.
5. Only an explicitly requested camera operation opens USB. Install and restore
   require fresh displayed battery confirmation >=75%, global ST selection and
   a fully reviewed per-body package. Never infer battery level from an old log.

## Standard interface

Use `python a7cr.py project --help`. JSON goes to stdout; progress and private log
locations go to stderr. Each `project run` performs one selected operation and
never retries, auto-resumes or advances to a write. Read its return code and log.
There is no generic downloaded firmware or universal installer.

`A7CR_PROJECT_ROOT` is set by the CLI for its trusted child process. Runtime
assets live in that project's `private/`; source and pinned dependencies remain
in this checkout. Do not change sources bound to an active package's receipts;
use an isolated checkout for development.

## Device invariants

- One service session at a time. Public project camera commands share a
  host-wide owner-scoped USB lock in addition to the backend project lock.
- Preserve current body calibration, unselected recipes/titles and native
  FL/FL2/FL3. Slot 1 CC is preserved when adding slots 2/3.
- Saved ST and actual runtime ST are separate checks. Native setters use
  slot-scoped compare-and-set under the original locks; re-probe all 18 bases
  after saving and after each native synchronization.
- Bind loaded-code and native reports to the same `(pid, base, boot_id)`.
  Kernel boot alone proves neither loaded CP RAM nor hardware correctness.
- Stop on timeout, unknown write result, unexpected bytes or foreign temporary
  files. Preserve evidence. Do not reauthenticate/replay the failed write.
- A USB-exit timeout may be inspected only by the narrow completed-install
  reviewer, which redecodes original reports and snapshots and requires a new
  cold-start read-only verification. Keep the original failure event.
- Only after all I/O and service exit end may the owner disconnect, power off,
  wait for the access light and remove the battery for the cold-start procedure.
- Confirm names, new photos, camera playback and existing looks separately.
  Metadata 249/250/251 confirms the custom route, not Fujifilm color fidelity.

## Development and publication

Run `python tools/run_tests.py`; relevant offline tests are listed in the
workflow guide. Tests mock device protocols; private-fixture skips are not passes.
Keep English and Chinese READMEs in sync. Retain upstream licenses and credits.
Before staging, run `python tools/audit_publication.py`. Stage explicit source
paths only; never force-add private data, firmware, DCP/LUTs or generated native
payloads. A7CR documents with no blanket software license are research references,
not material to relicense under MIT.
