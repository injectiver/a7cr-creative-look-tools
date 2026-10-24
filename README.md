# A7CR Creative Look Tools

**English** · [简体中文](README.zh-CN.md)

Python research tools for **Sony ILCE-7CR / A7CR firmware 2.01**: native FL2/FL3,
ST-relative custom Creative Looks, macOS USB capture, and offline DCP fitting.
The workflow works with any coding agent or a human using a terminal. No
particular agent client, MCP service or account is required.

**0.2.0-research** adds the single-slot **Classic Chrome** workflow and an
incremental **PRO Neg. Std + ASTIA / SOFT** extension, preserving the first slot.
These are fitted Sony adaptations. Look names do not establish a color match to
an original Fujifilm camera.

## What is included

- Source adapters, native worker sources, host planners and exact forward/inverse
  program windows for A7CR 2.01.
- Independent saved/runtime ST synchronization, slot-scoped compare-and-set,
  full program/resource readback and checks that preserve body calibration and
  unselected looks.
- A private-project CLI with **JSON stdout**, per-operation logs and separate
  checkpoint, preparation, emulation, installation, verification and restoration
  operations. Default inventory/status commands do not open USB.
- An inspected path for the observed **writes complete, ordinary USB return
  timed out** case. It never reinstalls; it redecodes the original reports and
  requires a new cold-start read-only verification while retaining the failure.
- [AGENTS.md](AGENTS.md), usable by shell-capable agents without client-specific
  APIs, plus English and Chinese workflow/validation documents.

No firmware containers, complete/patched components, per-body backups or
calibration, generated worker binaries, DCP/LUT files or personal photos are
bundled. Supply these locally and retain their applicable licenses.

## Tested scope

One A7CR 2.01 and one Apple Silicon Mac were used for the original reviewed
implementation. Native FL2/FL3 and single-slot CC were installed; the two-slot
portrait extension was then written, fully read back and machine-verified after
a new boot. New CC, PRO Neg. Std, ASTIA, ST, FL2 and FL3 JPEG samples were inspected
at the corresponding stages. The latest three samples are indoor still life,
not a skin-tone test. Complete physical restoration has not been exercised.

The portable project interface is covered by offline host tests. Moving private
paths into projects is not a new physical test on other bodies or hosts. USB
operations are macOS-only in this release; offline tools do not establish
Windows/Linux camera compatibility. The recorded environment and evidence
boundaries are in [validation](docs/VALIDATION.md).

This is unofficial firmware research. A wrong or interrupted write can prevent
a camera from starting. Keep verified private backups and use the exact-source
checks. Neither an emulator pass nor a changed kernel boot guarantees recovery.

## Setup

Use Python 3.12 and a dedicated environment:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-research.txt
python a7cr.py bootstrap --research
python a7cr.py doctor
```

`bootstrap` obtains the exact source commits in [upstream.lock.json](upstream.lock.json).
It does not obtain Sony firmware, profiles or a prepared camera job. An existing
mismatched checkout stops instead of being reset. Apple Silicon Keystone may
need its native library built from the pinned source; see the workflow guide.

## Agent-neutral private projects

```sh
python a7cr.py project init \
  --project private/projects/my-camera --firmware-version 2.01
python a7cr.py project status --project private/projects/my-camera
```

Initialization is local and creates no camera binding. The firmware argument is
an owner declaration, not identification proof. Private files stay in the
project's `private/`; code and pinned dependencies remain in the checkout.
Absolute paths and paths containing spaces are supported. Use one checkout per
active reviewed package, because editing its bound sources invalidates receipts.

A project is a workspace for **locally prepared, reviewed per-body packages**.
It is not a downloaded universal installer. The research builders still need
local Sony components, the verified FL23 baseline, local DCP/model inputs and
placement/loading evidence. The CLI stops when an input or validation receipt is
missing. Follow [the workflow](docs/WORKFLOW.md); do not manufacture missing
manifests or copy another body's package.

Each operation is explicit:

Supply the three original matching profiles locally, then fit them offline:

```sh
python a7cr.py project fit-profiles --project private/projects/my-camera \
  --classic-chrome /path/to/Classic_Chrome.dcp \
  --pro-neg-std /path/to/Pro_Neg_Std.dcp --astia /path/to/Astia.dcp \
  --use-upstream-model
```

This preset checks the reviewed original input hashes and requires explicit
acceptance of the provisional model. After preparing/verifying the local FL23
baseline, `--stage single --operation build-assets` rebuilds the first candidate,
placement/loading evidence, readers and recovery catalog. After installing and
machine-verifying CC, use `--stage portrait --operation build-assets` for the
increment. These operations are offline and do not authorize installation.

```sh
# Read-only capture; own-terminal administrator authorization is required.
sudo .venv/bin/python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation checkpoint

# Offline preparation from an explicitly selected completed checkpoint.
python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation prepare \
  --checkpoint private/projects/my-camera/private/portrait-slots-checkpoints/READ/checkpoint.private.json
python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation native-check
python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation finalize
python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation validate
```

`--stage single` selects the first-slot workflow; `--stage portrait` selects the
increment over a machine-verified single-slot CC baseline. A fresh checkpoint
is required for the new stage. `status` only reports recorded phases; `validate`
checks actual local artifacts, receipts and bound sources.

### Explicit writes and post-start checks

Only after successful local preparation, select **global ST** on the camera,
connect in **Image Transfer / MSC**, and use its **current displayed** battery
level, at least 75%. Example for an owner who has just read 90%:

```sh
sudo .venv/bin/python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation install --battery-percent 90
```

Do not paste 90 as an assumed level. The CLI never asks for or stores the Mac
password; `sudo` handles authorization in the owner's terminal. It performs one
operation and never auto-retries or auto-advances to another write.

While switching to service mode, do not select MSC again. Select it promptly
when the reads-ended message appears. After all I/O and service exit have ended,
disconnect USB, power off normally, wait for the access light, remove the battery
for at least 60 seconds, then reinstall it and start the camera. Check names,
new photos, playback and retained looks, reconnect in MSC, then:

```sh
sudo .venv/bin/python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation verify
```

`restore` uses the prepared exact inverse and fresh power confirmation. For the
portrait increment it returns to the preceding **single-slot CC** version;
selected fields are restored only while still equal to imported values, keeping
later user edits. It does not overwrite a whole settings snapshot.

Unknown results stop. `inspect-exit` is local-only; `review-exit` is the narrowly
scoped post-cold-start read-only completion check for the fully written portrait
case. Neither is a retry of installation or a general rescue procedure.

## Existing offline/read-only tools

`doctor`, descriptor-only `identify`, explicit current-state `backup`, local
`fit-dcp` and `analyze-photos` remain available. See `python a7cr.py --help` and
the workflow guide. A DCP fit is a non-installable candidate, not camera evidence.
The upstream model is provisional; use measured A7CR calibration when available.

## Development and attribution

```sh
python tools/run_tests.py
PYTHONPATH=.:device:offline python -m unittest \
  test_single_slot_candidate test_prepare_single_slot_installation \
  test_portrait_slots_candidate test_prepare_portrait_slots_installation \
  test_portrait_slots_runtime
python tools/audit_publication.py
```

Tests mock device protocols. Private-fixture skips are recorded separately from
passes. Native instruction and transaction evidence is distinguished from Sony
function stubs, full-size hash oracles, physical boot, photo acceptance and
restoration in [validation](docs/VALIDATION.md).

Foundations: [QAQLeonard/A7C II](https://github.com/QAQLeonard/a7c2-fl23-research),
[lzh2016zzz/A7CR research](https://github.com/lzh2016zzz/a7cr-fl23-research),
[MDHan/macOS](https://github.com/MDHan/a7c2-fl23-macos) and
[Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE). Retained licenses and profile
attribution: [NOTICE.md](NOTICE.md). The software license does not relicense Sony
firmware or independently supplied assets. This project does not imply upstream
or camera/profile-vendor endorsement.
