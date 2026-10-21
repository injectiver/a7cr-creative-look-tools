# Sources, attribution, and distribution boundaries

[English README](README.md) · [简体中文](README.zh-CN.md)

This is a downstream A7CR adaptation and research companion. The underlying
FL2/FL3 and custom-look methods are credited to the projects below. Their
authors have not endorsed this repository.

| Source | Used for | Pinned reference / notice |
|---|---|---|
| [QAQLeonard/a7c2-fl23-research](https://github.com/QAQLeonard/a7c2-fl23-research) | FL23 native-worker design, service/backup protocol integration, DCP look/tone conversion, custom-look runtime, names, compressed backups and validation methods | `b51688deecb56cd34fdd1f2948915cd6ea4e6736`; [retained MIT](licenses/A7CII-MIT.txt), Copyright 2026 A7C II FL2/FL3 preview contributors |
| [lzh2016zzz/a7cr-fl23-research](https://github.com/lzh2016zzz/a7cr-fl23-research) | A7CR 2.01 offsets, native FL23 dispatch/metadata/defaults/WBI research | `43ba74441c8f10459ade41e84a379ad8005e6ef4`; research reference, not a declaration that its entire document is MIT-licensed |
| [MDHan/a7c2-fl23-macos](https://github.com/MDHan/a7c2-fl23-macos) | macOS IORegistry ownership/unmount/capture approach adapted in `device/mac_usb.py` | `dd697995c85ddf32ca9ce19b870d048769fadc91`; [retained MIT](licenses/MDHan-MIT.txt) |
| [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) | Sony service and Backup protocol Python library, supplied through the pinned A7C II checkout | Upstream pin `a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0`; [retained MIT](licenses/Sony-PMCA-RE-MIT.txt), Copyright 2015 ma1co |
| [DavidBuchanan314/fwtool.py](https://github.com/DavidBuchanan314/fwtool.py) | Local firmware container analysis dependency | `3955d7890fc38daf942bb52827599bfe35de4a14`; acquired separately with its original notices |
| [keystone-engine/keystone](https://github.com/keystone-engine/keystone) | Assembly dependency / native Apple Silicon library build | `dc7932ef2b2c4a793836caec6ecab485005139d6`; acquired separately with its original notices |
| [ExifTool](https://github.com/exiftool/exiftool) | Selected photo metadata extraction | `2200871d9cef988051d2a99d67df3bda6cbb30a8` (13.59); acquired separately with its original notices |

The repository contains host source, assembly-generation logic, firmware offsets,
hashes, and short instruction signatures/patch fragments needed to describe the
adaptation. It does **not** claim to contain no Sony-related reverse-engineering
information. The MIT license is not a license for Sony's proprietary assets.

The published source does not bundle official update containers, complete or
modified Sony firmware components, extracted factory gamma/chroma/matrix tables,
per-body calibration/settings backups, generated native payloads, DCP/LUT assets,
camera identifiers, or private photographs. Such inputs/outputs stay local under
ignored directories. Do not upload them in issues or pull requests.

`bootstrap` retrieves pinned **upstream source checkouts** into ignored
`research/`. Those repositories retain their own licenses and reference-asset
notices; downloading or calling them does not relicense them. This repository
does not mirror their release binaries or original DCP attachments.

## DCP reference attribution

The six-look experiment used six selections from the **18 original DCP files**
in the [A7C II project's release downloads](https://github.com/QAQLeonard/a7c2-fl23-research/releases),
described in its [profile guide](https://github.com/QAQLeonard/a7c2-fl23-research/blob/b51688deecb56cd34fdd1f2948915cd6ea4e6736/docs/en/profiles.md).

- Fujifilm-style adaptations: 门萨特里顿 / MTriton; the supplied notices also
  credit `abpy/FujifilmCameraProfiles` and **CC BY-NC-SA 4.0**. Preserve attribution,
  indicate modifications, and apply the relevant noncommercial/share-alike terms.
- Ricoh GR III adaptations: 爸总林先森. The supplied files retain embedded Adobe
  copyright notices and the upstream manifest states that no separate
  redistribution license was supplied. This repository does not redistribute
  those profiles or presume that its software license covers them.
- A converted 1,215-byte table is not automatically free of the source profile's
  applicable rights. Generated data need their own provenance review before
  publication.

## 简体中文说明

本项目是基于上述上游成果的 A7CR 适配与研究工具，不声称首次发明 FL2/FL3
或 DCP 导入方法。MIT 仅适用于对应的软件代码；原作者署名及第三方许可保留。
A7CR 研究仓库在此作为研究来源引用，并不把其全部文档重新声明为 MIT。

公开源码包含偏移、哈希、汇编生成逻辑和少量指令签名／补丁片段；不随仓库提供
完整或修改后的 Sony 固件、抽取的原厂色彩／校准表、机身备份、DCP/LUT、个人照片
或相机标识。所需输入由使用者自行提供，生成物留在本地忽略目录。

六款参考 DCP 来自 A7C II 项目的 18 款原始文件附件。富士风格与理光风格文件的
来源和授权分别处理，不能用软件 MIT 许可覆盖。首版仅提供上游入口，不打包素材。
