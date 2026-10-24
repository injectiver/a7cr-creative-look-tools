# Validation and limitations

[English](VALIDATION.md) · [简体中文](VALIDATION.zh-CN.md) · [README](../README.md)

Recorded on 2026-10-20/21, Asia/Shanghai. All original firmware, per-body data,
native payloads, logs with identifiers and photo files remain private. This
document publishes selected non-identifying results and their practical limits.

## 0.2 update — 2026-10-25

The reviewed local implementation completed the single-slot CC installation,
then an incremental PRO Neg. Std/ASTIA extension. The increment's complete AP/CP
and all 68 resources matched the target. After a new boot, all 16 loaded AP
spans and both saved/native ST bases matched. Three new 9504×6336 JPEGs carried
markers 250, 251 and 0, at 1/30 s, f/2.8, ISO 400; full decoding and inspected
views showed no obvious corruption or abnormal bands. These were indoor still
life, not a skin-tone comparison. Full in-camera playback combinations and
complete physical restoration remain separate acceptance work.

The recorded USB-return timeout occurred after program/resource/settings/WBI
completion and service exit. Original binary reports and snapshots were
redecoded before a new cold-start read-only session; the original failure was
preserved, and the later verification succeeded without reinstallation.

The portable interface passed 283 public host tests (234 passes, 49 explicit
private-fixture skips) and 65 relevant offline tests (48 passes, 17 skips), with
zero failures/errors. A new independent private project fitted the local inputs
and rebuilt the first-slot candidate to the original AP/CP hashes, including
placement/loading evidence, 7-case readers, a 5-case native probe and the
23-variant recovery catalog. No camera was opened for this rebuild. The portable
API itself has not been physically tested on a second body.

[Machine-readable scope](../validation/creative-look-validation.json). These
records exclude private IDs, binding digests, raw logs, firmware, profiles and
photos. The earlier 0.1 record follows.

## Historical 0.1 release checks

- Public host suite: **127 tests: 84 passed, 43 skipped, 0 failures/errors**.
  Device protocols are mocked; no camera is opened. Skips represent deliberately
  unavailable private per-body manifests/fixtures, not successful integrations.
- `doctor` and help/argument checks run without USB. Descriptor identification is
  tested as a separate explicit entry point.
- The new offline DCP CLI was run against a privately held original Classic Neg.
  profile and the pinned shared model:1,215-byte output; synthetic RGB MAE
  `0.029678829642877286`. The output stayed private and non-installable. This is
  not measured A7CR accuracy.
- The new photo CLI was run on two selected existing A7CR RAW+JPEG pairs. RAW and
  JPEG counts matched the previous local analysis; original files were unchanged.
- Publishing uses a source allowlist, text-only assets and a privacy/asset audit.
  The release includes no original photo demonstration or firmware attachment.

See [public-tests.json](../validation/public-tests.json) and
[environment.json](../validation/environment.json). A local software run does
not certify arbitrary camera installation or long-term stability.

## Historical camera / native evidence

| Area | Evidence recorded | What it does not prove |
|---|---|---|
| Native FL23 | One A7CR 2.01 completed staged writes/full readback and captured fresh FL/FL2/FL3 files with corresponding numeric metadata | Exact matching to a physical Alpha 1 II; all shooting combinations |
| Six-slot port |15616 AP instruction-path cases,103 CP controller/builder/uploader scenarios,512 gamma normalization cases; source/inverse and placement checks | Full RTOS/ISP/hardware timing simulation |
| CP load/bootstrap | A local instruction replay reached main after 62,873 ARM instructions without overwriting the proposed table area | Direct capture of running camera CP memory |
| Six installation | CP and68 names were written/read back; AP-only completion then verified programs/settings/WBI without repeating CP/name writes | Completed post-cold-start machine verification plus physical acceptance of all six slots |
| Resource boundary | Complete known file read via checked padded temporary copy; framing and native failure models | Generic cure for USB timeouts or proven hardware reliability |
| Runtime reader | Actual loaded AP spans were checked at recorded earlier stages;16-span post-six reader prepared and simulated | That its final six-look pass has been physically completed; running CP content |
| Backups | Two byte-verified FL23 backups and independently reconstructable compressed six-look checkpoints | Separate-disk disaster recovery; proven complete physical rollback |

The final six-look local job was recorded as `INSTALLED_PENDING_COLD_START`.
Later native FL23 photographs are real evidence of that path, but they do not
close all six custom-slot acceptance items. This release preserves the distinction
instead of converting an installation receipt into a broader success claim.

## Exposure investigation: native FL2, not DCP tables

Three initial FL/FL2/FL3 samples at ISO400,F2,1/100 showed a different output white
level. RAW saturation was present in all three. FL had a different recipe
(including contrast-3, shadows+4, saturation+4) from FL2/FL3, so it was not a
matched-recipe calibration comparison. All used automatic white balance.

A subsequent native FL2 series kept ISO400/F2 and Highlights-9 and varied shutter:

| Shutter | RAW samples at upper limit16383 | JPEG pixels with all RGB channels255 |
|---|---:|---:|
|1/400|0.3204426%|0.1495699%|
|1/800|0.2252972%|0.0986626%|
|1/1600|0.1264984%|0.0510551%|
|1/3200|0.0037282%|0.0026006%|

Percentages refer to each full representation; RAW photosites and JPEG RGB
pixels are different measurements. Bayer groups with all four samples clipped
were absent by1/1600, while individual channels still clipped. At1/3200, a
small-neighborhood comparison placed about98% of the remaining nearly-white
blocks near high RAW levels; this tolerated small geometric offsets and is not
exact lens-correction registration.

The supported conclusion is that reducing capture exposure reduced saturation
and recovered highlight structure; this series did not show a large
exposure-independent white plateau. A JPEG value255 or a zebra indication alone
does not measure stored RAW headroom. This is **not** a claim that a gamma bug was
fixed, that every possible processing defect is absent, or that original Sony
FL2/FL3 tone/color is exactly reproduced.

In M mode with fixed ISO, exposure compensation does not change exposure; Sony
documents compensation in M with ISO AUTO. Actual shutter/aperture/ISO changes
are needed for that test. See [Sony exposure compensation](https://helpguide.sony.net/ilc/2370/v1/zh-cn/contents/0406B_exposure_compensation.html)
and [zebra](https://helpguide.sony.net/ilc/2370/v1/zh-cn/contents/0406M_zebra_display.html).

## Separate provisional DCP highlight study

Before the owner clarified the affected look names, the six DCP-derived tables
were studied offline. Under the shared provisional model, several gray ramps
reached white before input1. An uninstalled neutral-node diagnostic table study
removed that predicted early gray clipping without changing midgray. It did not
establish the cause of the native FL2 samples and was **never installed as their
fix**. The study scripts remain clearly labelled non-installable research.

The shared rendering exposure parameter is about+0.48stops. Removing it in an
offline reference comparison shifted midgray as well as highlights; it is not a
validated A7CR correction. Multi-scene neutral/skin/saturated-color validation and
a measured A7CR bridge remain outstanding.

## Known limitations to keep explicit

- A current saved recipe, a factory reset default, visible name, numeric metadata,
  preview and new photo are separate checks. ST base binding is editable.
- A prior MR memory mode masked FL23 changes; ordinary P/A/S/M and fresh photos
  were needed to discriminate state from processing.
- The upstream preview retry strategy adds work. Frame rate, power, heat and
  long-term preview stability were not measured here.
- Some older reports compared overly broad telemetry and stopped on changes
  outside the writable-setting scope. The relevant comparison now preserves
  writable AP settings and four CP units, while retaining other snapshots.
- A completed disk write can coexist with older loaded code / retained WBI.
  AP runtime checks and a new boot do not directly prove CP runtime tables.
- No other model/firmware/region/host combination, video, exhaustive RAW/HEIF/burst
  matrix or physical complete recovery is validated by this release.
