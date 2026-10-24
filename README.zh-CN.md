# A7CR Creative Look Tools

[English](README.md) · **简体中文**

面向 **Sony ILCE-7CR / A7CR 固件 2.01** 的 Python 研究工具：原生 FL2/FL3、
以 ST 为基础的自定义创意外观、macOS USB 接管，以及离线 DCP 拟合。
人和各类具备终端能力的 coding agent 都能使用，不依赖特定客户端、MCP 或账号。

**0.2.0-research** 加入单槽 **Classic Chrome** 流程，以及保留槽 1、向槽 2/3
增量添加 **PRO Neg. Std + ASTIA / SOFT** 的流程。这些是 Sony 上的拟合版本，
不能仅凭外观名称认定色彩与富士原机相同。

## 提供的内容

- A7CR 2.01 适配源码、原生 worker 源码、主机规划，以及精确的程序正向／逆向窗口。
- 分开核对保存值与实际运行 ST；仅针对选中槽的原生锁内比较后写入；完整程序／资源
  读回；保留本机校准、未选槽和原有外观的检查。
- 输出 **JSON stdout** 的私人项目 CLI，分别执行检查点、准备、模拟、安装、核验、
  还原；每次操作保留独立日志。默认环境／状态检查不打开 USB。
- 对实际遇到的“写入已结束、等待普通 USB 返回超时”提供受限核查：重解码原始报告，
  冷启动后重新只读核验，保留失败记录；不会重新安装。
- 通用 [AGENTS.md](AGENTS.md) 和中英文流程／验证文档，不需要某一家的 agent API。

仓库不附带固件包、完整或修改后的固件组件、逐机备份／校准、生成的原生二进制、
DCP/LUT 或私人照片。使用者在本机提供相应输入，并保留各自适用的许可。

## 实测范围

原始经过审核的实现使用一台 A7CR 2.01 和一台 Apple Silicon Mac。原生 FL2/FL3、
单槽 CC 已安装；随后新增两个人像槽，完成写入、完整读回和新启动后的机器核验。
对应阶段检查过 CC、PRO Neg. Std、ASTIA、ST、FL2、FL3 的新 JPEG。最近三张为
室内静物，不是肤色测试。完整实机恢复尚未演练。

通用项目接口经过电脑端离线测试。路径改为私人项目，并不等于在其他机身或系统上
做过新实测。本版相机 USB 操作只支持 macOS；离线工具不代表 Windows/Linux
相机操作已兼容。环境记录与证据范围见[验证说明](docs/VALIDATION.zh-CN.md)。

这是非官方固件研究。错误或中断的写入可能导致相机无法启动。保留核验过的私人
备份，使用精确来源检查。模拟器通过或内核启动标识改变都不等于保证可以恢复。

## 准备环境

使用 Python 3.12 和独立虚拟环境：

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-research.txt
python a7cr.py bootstrap --research
python a7cr.py doctor
```

`bootstrap` 获取 [upstream.lock.json](upstream.lock.json) 固定提交的源码，
不下载 Sony 固件、DCP 或已准备好的机身安装任务。已有上游目录提交不符时会停止，
不会重置。Apple Silicon 上的 Keystone 可能需要从固定源码编译原生库，参见流程文档。

## 通用 agent 私人项目

```sh
python a7cr.py project init \
  --project private/projects/my-camera --firmware-version 2.01
python a7cr.py project status --project private/projects/my-camera
```

初始化只创建本地项目，不读取或绑定相机。版本参数是使用者的声明，不是识别证据。
私人文件保存在项目的 `private/`，源码和固定依赖保留在当前代码检出中。支持绝对路径
和带空格的路径。每个活动安装包使用独立代码检出；改动已绑定的源码会使收据失效。

项目用来管理**在本机逐机准备并审核的安装包**，不是下载即可刷入所有机身的安装器。
研究构建器仍需要本地 Sony 组件、已核验的 FL23 基线、DCP／模型输入及放置／加载证据。
缺少输入或收据时 CLI 会停止。按[流程文档](docs/WORKFLOW.zh-CN.md)准备，
不要编造缺失清单，也不要复制另一台机身的安装包。

每个步骤独立、显式执行：

在本机提供三份匹配的原始素材，再离线拟合：

```sh
python a7cr.py project fit-profiles --project private/projects/my-camera \
  --classic-chrome /path/to/Classic_Chrome.dcp \
  --pro-neg-std /path/to/Pro_Neg_Std.dcp --astia /path/to/Astia.dcp \
  --use-upstream-model
```

此预设核对原始输入哈希，并要求显式接受暂定模型。准备并核验本机 FL23 基线后，
使用 `--stage single --operation build-assets` 重建首槽候选、放置／加载证据、读取器
与恢复目录；安装 CC 并通过机器核验后，再用 `--stage portrait --operation build-assets`
构建增量。这些命令只离线生成工件，不授权安装。

```sh
# 只读检查点；管理员授权在使用者自己的终端完成。
sudo .venv/bin/python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation checkpoint

# 从明确选定的完整检查点离线准备。
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

`--stage single` 对应首次单槽流程；`--stage portrait` 对应在机器核验过的单槽 CC 上
增量添加两槽。新阶段必须有新鲜检查点。`status` 只报告已记录的阶段；`validate`
才会核对实际工件、收据与绑定的源码。

### 显式刷写与启动后检查

只有本机准备成功后，才在相机选择创意外观列表里的 **ST**，连接并选
**影像传输／MSC**。屏幕上的**当前实际电量**至少为 75%。下面仅举刚查看到 90% 的例子：

```sh
sudo .venv/bin/python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation install --battery-percent 90
```

不要把示例的 90 当作推定电量。CLI 不读取或保存 Mac 密码，管理员授权由使用者
终端的 `sudo` 完成。每次只执行所选操作，不会自动重试、继续或推进到下一次写入。

切换服务模式期间不要再次选 MSC；出现“读取已结束”后，及时按相机提示选择。
全部 I/O 和服务退出结束后，断开 USB、正常关机，等存取灯熄灭，取出电池至少
60 秒，再装回开机。分别检查名称、新照片、相机回放和原有外观，重连 MSC 后运行：

```sh
sudo .venv/bin/python a7cr.py project run --project private/projects/my-camera \
  --stage portrait --operation verify
```

`restore` 使用已准备的精确逆向及新鲜电量确认。人像增量的恢复目标是之前的
**单槽 CC**；仅当参数仍等于导入值时才恢复检查点值，保留之后由使用者改动的项目。
不会覆盖整份设置快照。

未知结果会停止。`inspect-exit` 只检查本机文件；`review-exit` 仅用于已经完整写入的人像
增量在冷启动后的只读收尾核验。两者都不是重刷，也不是通用救砖流程。

## 原有离线／只读工具

仍提供 `doctor`、仅描述符的 `identify`、显式当前状态 `backup`、本地 `fit-dcp`
与 `analyze-photos`。查看 `python a7cr.py --help` 和流程文档。DCP 拟合只生成
不可直接安装的候选表；共享上游模型仍是暂定模型，有实测 A7CR 校准时应优先使用。

## 开发、署名与许可

```sh
python tools/run_tests.py
PYTHONPATH=.:device:offline python -m unittest \
  test_single_slot_candidate test_prepare_single_slot_installation \
  test_portrait_slots_candidate test_prepare_portrait_slots_installation \
  test_portrait_slots_runtime
python tools/audit_publication.py
```

测试中的设备协议使用模拟。私有样本跳过项单独记录，不计为通过。
[验证说明](docs/VALIDATION.zh-CN.md)分别记录原生指令／事务模拟、Sony 函数桩、
全尺寸哈希 oracle、实际启动、试拍和恢复的证据范围。

基础来自 [QAQLeonard/A7C II](https://github.com/QAQLeonard/a7c2-fl23-research)、
[lzh2016zzz/A7CR 研究](https://github.com/lzh2016zzz/a7cr-fl23-research)、
[MDHan/macOS](https://github.com/MDHan/a7c2-fl23-macos) 和
[Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE)。保留的许可与素材署名见
[NOTICE.md](NOTICE.md)。软件许可不会自动覆盖 Sony 固件或另行提供的素材，
也不暗示上游作者、相机厂商或素材作者为此适配背书。
