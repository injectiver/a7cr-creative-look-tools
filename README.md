# A7CR Creative Look Tools

**English** · [简体中文](README.zh-CN.md)

Research source and host tools for **Sony ILCE-7CR / A7CR firmware 2.01**:
native FL2/FL3 adaptation, a six-slot ST-relative custom-look port, macOS USB
handling, and RAW/JPEG highlight diagnostics.

**Release status: `0.1.0-research`. One A7CR and one Apple Silicon Mac were used.**
The public CLI provides environment checks, descriptor-only identification,
explicit read-only backups, offline DCP fitting, and local photo analysis.
The installation/native-worker sources are included as research interfaces;
this release does not expose a generic `install` command or ship a flashable
firmware image. Several historical builders still require a reviewed private
workspace with case-specific paths. See [the research workflow](docs/WORKFLOW.md).

This is unofficial work. Firmware modification can prevent a camera from
starting. Full file readback, an emulator pass, or a new kernel boot is not proof
of complete hardware behavior or recoverability. No physical complete rollback
or arbitrary-camera installation claim is made.

## What this repository contributes

The FL23 and DCP/custom-look foundations come from
[QAQLeonard's A7C II tools](https://github.com/QAQLeonard/a7c2-fl23-research) and
[lzh2016zzz's A7CR research](https://github.com/lzh2016zzz/a7cr-fl23-research).
This repository documents and implements the A7CR-side adaptation and the tested
macOS workflow, including:

- A7CR-specific native FL23 selection, metadata/defaults, and exact-source
  processing patches, preserving the camera's own calibration.
- An A7CR six-slot custom-look adapter, bounded AP/CP helper placement, resource
  names, ST recipe bindings, and preservation of native FL/FL2/FL3.
- Camera-scoped macOS storage ownership checks before non-forced unmount and
  USB capture, adapted from MDHan's work.
- Inspection and narrowly scoped continuation of known interrupted phases,
  rather than replaying writes whose outcome is unknown.
- A checked temporary padded-copy reader for one observed final-512-byte
  transfer boundary, with original resources preserved.
- Reproducible RAW/JPEG measurements that distinguish stored RAW saturation
  from an output JPEG reaching white.

See [NOTICE.md](NOTICE.md) for source attribution and licenses. These are
adaptation and validation contributions, not a claim to have invented the
underlying camera protocol, FL23 method, or DCP format.

## Capability and validation scope

| Area | Available here | Evidence / limit |
|---|---|---|
| Host environment | `doctor` | Runs without opening USB; excludes serials/hostnames |
| USB identification | `identify` | Product/interface descriptors only; no service authentication |
| Current-state backup | `backup` | Explicit service session; two independently byte-verified local copies; no persistent camera writes |
| DCP conversion | `fit-dcp` | Offline native-shaped candidate only; no firmware/job is generated |
| RAW+JPEG analysis | `analyze-photos` | Tested against selected A7CR pairs; originals remain unchanged |
| Native FL2/FL3 | Research sources in `offline/` and `device/` | Installed and photographed on one A7CR 2.01; not compared to a physical Alpha 1 II |
| Six custom slots | Research sources | Program/resource/settings writes and full readback completed on one body; full post-cold-start machine verification and all six physical acceptances are not recorded as complete |
| Installation / restoration | Research interfaces | Exact-source, per-body artifacts and review required; not a supported public one-command installer |
| Other bodies, OSes, firmware | Not established | Do not reuse the offsets or claims for other combinations |

## Tested computer and software

These are the **actual research host details**, not minimum requirements or a
statement that all similar Macs work.

| Item | Recorded environment |
|---|---|
| Computer | MacBook Pro, model identifier `Mac16,8` |
| SoC / CPU | Apple M4 Pro; 12 CPU cores (8 performance + 4 efficiency) |
| Memory | 24 GB |
| Architecture | `arm64` / Apple Silicon |
| macOS | 27.2, build `26B5091g` |
| Shell | zsh |
| Python | 3.12.14 in a dedicated virtual environment |
| USB runtime | PyUSB 1.3.1, libusb-package 1.0.30.0 |
| Numeric / image tools | NumPy 2.5.4, SciPy 1.18.1, rawpy 0.27.1 / LibRaw 0.22.1, Pillow 13.0.0 |
| Research tools | Capstone 5.0.6, pyelftools 0.32, Unicorn 2.1.4, Zig 0.13.0, Keystone 0.9.2 |
| Native build support | CMake 3.31.10; Keystone shared library built for arm64 from the pinned official source |
| Metadata tool | ExifTool 13.59, fixed source commit |
| Camera | One Sony ILCE-7CR, firmware shown as 2.01 |

No Mac serial number, hardware UUID, hostname, username, personal absolute path,
camera serial/hash binding, or original photograph is included in this public
environment record. Machine-readable details: [validation/environment.json](validation/environment.json).
Intel Macs, Windows/Linux camera access, other macOS releases and other bodies
were not physically tested by this project.

## Setup

Download/extract this repository or clone it, then open its root in Terminal.
Use a Python 3.12 interpreter to reproduce the recorded environment:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python a7cr.py bootstrap
python a7cr.py doctor
```

`bootstrap` uses Git and network access once to obtain the exact upstream source
commits in [upstream.lock.json](upstream.lock.json). Existing mismatched
checkouts are rejected instead of reset. Original upstream notices remain in
those local checkouts. It does not fetch a Sony update container or DCP release
attachment. Cached matching checkouts can be used without fetching them again.
Git and Perl must be available for checkout/ExifTool; research builds additionally
need native build tools. The virtual environment and all fetched sources are
ignored by Git.

### Environment check

```sh
python a7cr.py doctor
```

This reports Python/architecture, selected package versions and pin status.
It does not enumerate USB, query hardware serial numbers, authenticate a camera,
unmount storage, or open a device.

## Public commands

### Identify the connected camera

Set the camera to **Image Transfer / Mass Storage (MSC)** and connect it directly
to the Mac. Then:

```sh
python a7cr.py identify
```

This command lists Sony USB product/interface descriptors without serial output
or service authentication. The observed normal A7CR identity was `054c:0e86`;
the service identity is `054c:0336`. A PID alone is not sufficient model proof.

### Read a current-state backup

Confirm the camera's displayed firmware version yourself. The two destination
directories must be fresh, distinct and not nested inside one another:

```sh
sudo .venv/bin/python a7cr.py backup \
  --firmware-version 2.01 \
  --workspace private/backups/camera-01-a \
  --backup-copy private/backups/camera-01-b
```

Administrator authorization is entered in your own Terminal, not supplied to the
program as text. On macOS the reader verifies that storage belongs to the exact
A7CR, uses non-forced unmounts, then captures that camera's interface.

Important timing: begin in MSC. While the program is switching to service mode,
**do not press the camera's USB/MSC selection**. A macOS accessory-allow prompt
can be accepted. Select MSC again only after the explicit “读取已结束” / reads-ended
message. Authentication is not automatically repeated after an unknown result.

The eight saved files are AP/CP components, live/saved Backup snapshots, and four
CP units extracted from those snapshots. Redundant direct READ40 of CP unit00
is deliberately omitted after an observed timeout. Files are verified in both
destinations and stored with private permissions. This backs up the **current
state**, which may already be modified; it does not manufacture a stock backup.

Two directories on one Mac disk do not protect against loss of that disk. The
manifest reports this. Choose a separate physical destination when available.
Keep complete backups private. A read failure or unknown service state stops
the session and preserves evidence; do not blindly rerun it.

### Fit a DCP locally

Get the original profile yourself through the
[upstream profile guide](https://github.com/QAQLeonard/a7c2-fl23-research/blob/b51688deecb56cd34fdd1f2948915cd6ea4e6736/docs/en/profiles.md).
This repository provides no DCP or precomputed LUT attachment.

Prefer a measured calibration:

```sh
python a7cr.py fit-dcp /path/to/profile.dcp \
  --name "My Look" --slot 1 \
  --calibration /path/to/measured-model.json \
  --output private/fits/my-look-01
```

For an explicitly provisional experiment with the shared upstream A7C II model:

```sh
python a7cr.py fit-dcp /path/to/profile.dcp \
  --name "My Look" --slot 1 --use-upstream-model \
  --output private/fits/provisional-01
```

The result is a 1,215-byte signed-7 correction table plus a local report. It is
**not an installation job**. The converter uses DCP LookTable/tone stages, not
the full Adobe RAW pipeline. The supplied one-scene model is not measured A7CR
calibration; a low synthetic fit error is not a camera color-matching score.
The report also records a provisional neutral highlight check. It is not an
IRE measurement or sensor exposure percentage. Do not remove the model's
rendering exposure parameter as a blanket highlight fix; this also changes
midtones.

All imported slots require **actual base ST**. The camera base picker is editable,
not locked. This differs from native FL2/FL3, which use their own processing
records. A fitting candidate proves neither binding nor loaded/physical output.

### Analyze a RAW+JPEG exposure series

Supply explicitly selected `.ARW` + `.JPG` pairs. The tool reads them directly
and creates a new output directory; it does not edit/copy-over the originals:

```sh
python a7cr.py analyze-photos \
  --input /path/to/DCIM/100MSDCF \
  --stems DSC00001 DSC00002 DSC00003 \
  --output private/analysis/exposure-01
```

Only selected metadata tags are requested. Outputs include local metadata,
RAW upper-limit counts, JPEG white counts and scaled previews. GPS and serial
fields are not requested. Local metadata can still contain source file paths,
so review it before sharing. This command currently supports 2x2 Bayer
RAW+JPEG pairs, not HEIF-only input or a full color-calibration workflow.

The A7CR exposure experiment is documented in
[validation and limitations](docs/VALIDATION.md). Four native FL2 captures at
ISO400/F2, from 1/400 to 1/3200, showed RAW saturation and JPEG white areas
decreasing with exposure. This did not establish a stuck white mapping or an
exposure bug fix, and it did not validate six imported DCP looks.

## Research installation source

Read [WORKFLOW.md](docs/WORKFLOW.md) and [VALIDATION.md](docs/VALIDATION.md) before
using `offline/` or `device/` research interfaces. They include program builders,
native transaction generation, preflight, selected settings, resources, WBI,
inspection and post-reload checks. Several paths intentionally describe the
original case and require a new reviewed workspace; its private manifests and
payloads are not shipped. The old per-session shell launchers are excluded.

The tested flow separates program writes, names, recipes, WBI, cold power-off,
loaded AP checks and physical photos. A completed CP write is not repeated merely
because a later name read times out. Only a proven eligible continuation is
allowed. Existing generic user settings and body calibration must be preserved.
Physical full restoration remains untested; a software inverse is not proof of
hardware recovery.

## Offline tests

```sh
python -m pip install -r requirements-research.txt
python tools/run_tests.py
python tools/audit_publication.py
```

Recorded public host run: **127 tests, 84 passed, 43 skipped, 0 failures/errors**.
Private per-body integration fixtures are intentionally excluded; skips are not
passes. All device protocols in this suite are mocked. Native/emulator studies
and historical hardware evidence are separate categories, described in
[validation/public-tests.json](validation/public-tests.json) and the validation guide.
On the original restricted execution environment, some Unicorn ARM simulations
required execution outside that process sandbox; this is not a camera permission
or proof of hardware behavior.

## Repository map

```text
a7cr.py                 public host/offline entry points
tools/                  dependency pins, DCP fitting, photo analysis, tests/audit
device/                 A7CR readers, macOS ownership, research transactions/tests
offline/                source analysis, patch/native-worker builders and checks
docs/                   English / Chinese research workflow and validation
licenses/               retained upstream software notices
validation/             sanitized environment and public test summaries
private/, research/     local only; ignored; never published
```

## Licenses and contributing

Corresponding software is MIT-licensed with retained upstream notices. Sony
firmware, extracted factory color/calibration assets, DCP/LUT data and user
photos are not covered by that grant. See [NOTICE.md](NOTICE.md).

Report the model/firmware, host OS/build/architecture, command and a **redacted**
failure phase. Preserve unknown-outcome journals locally. Do not attach firmware,
body backups, calibration, identifiers or private photos. Contributions should
include reproducible software tests and distinguish simulation/readback/load/
physical evidence. New models/firmware need separate exact-source work; changing
a model check or reusing offsets is not an adaptation.
