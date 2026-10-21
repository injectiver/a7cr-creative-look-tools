# A7CR Creative Look Tools

[English](README.md) · **简体中文**

面向 **Sony ILCE-7CR / A7CR 固件 2.01** 的研究源码与电脑端工具：原生
FL2/FL3 适配、六个以 ST 为基础的自定义外观槽、macOS USB 操作，以及
RAW/JPEG 高光诊断。

**当前版本：`0.1.0-research`。实测范围为一台 A7CR 和一台 Apple Silicon Mac。**
公开 CLI 提供环境检查、仅描述符识别、显式只读备份、离线 DCP 拟合与本地照片分析。
安装程序和原生阶段源码作为研究接口提供；首版没有通用 `install` 命令，也不提供
可直接刷入的固件。若干历史构建脚本仍要求经过审核的私人工作目录和对应任务路径。
参见[研究流程](docs/WORKFLOW.zh-CN.md)。

这是非官方研究。修改固件可能导致相机无法启动。完整文件读回、模拟器通过或新的
内核启动，都不能证明全部实机行为正确或保证恢复。没有在任意机身安装、完整实机
回退或救砖能力的承诺。

## 贡献与来源

FL23 与 DCP／自定义外观的方法基础来自
[QAQLeonard 的 A7C II 工具](https://github.com/QAQLeonard/a7c2-fl23-research)及
[lzh2016zzz 的 A7CR 研究](https://github.com/lzh2016zzz/a7cr-fl23-research)。
本项目整理并实现 A7CR 侧适配与本次实际使用的 macOS 流程，包括：

- A7CR 对应的原生 FL23 选择、元数据／默认值与精确来源的处理补丁，保留本机校准。
- A7CR 六槽自定义外观适配、AP／CP 代码与数据边界、菜单资源名称、ST 配方绑定，
  以及保留原有 FL／FL2／FL3 的检查。
- 基于 MDHan 工作改编的 macOS 相机磁盘归属核对、非强制卸载和 USB 接口捕获。
- 写入中断后先核对已完成阶段，再只收尾确实未执行的部分；不盲目重复未知结果的写入。
- 针对一次最终数据长度落在 512 字节边界的超时，采用经过核验的临时填充副本读取，
  保留原始资源。
- 可复现的 RAW/JPEG 数值分析，将 RAW 已到上限与 JPEG 输出为白色分开判断。

这些属于适配、实现和验证贡献，不声称首次发明相机协议、FL23 方法或 DCP 格式。
完整署名与许可见 [NOTICE.md](NOTICE.md)，不暗示上游作者为本项目背书。

## 能力与验证范围

| 内容 | 本仓库提供 | 已有证据与限制 |
|---|---|---|
| 电脑环境 | `doctor` | 不打开 USB，不读取电脑序列号或主机名 |
| USB 识别 | `identify` | 仅产品／接口描述符，不进行服务认证 |
| 当前状态备份 | `backup` | 显式进入服务会话；两份独立按字节核验的本地副本；不持久写入相机 |
| DCP 转换 | `fit-dcp` | 仅离线原生形状候选表，不生成固件或安装任务 |
| RAW+JPEG 分析 | `analyze-photos` | 已对选定 A7CR 文件对验证；不修改原片 |
| 原生 FL2／FL3 | `offline/`、`device/` 研究源码 | 一台 A7CR 2.01 已安装并拍摄；未与实体 Alpha 1 II 做一致性标定 |
| 六个自定义槽位 | 研究源码 | 一台机身完成程序／资源／设置写入和完整读回；完整断电后的机器核验及六槽逐一实拍验收尚未记录为完成 |
| 安装与还原 | 研究接口 | 要求逐机准备和审核精确来源、备份与清单；不是面向所有机身的一条安装命令 |
| 其他机身／系统／固件 | 尚未建立 | 不能直接沿用这里的偏移或验证结论 |

## 本次实际使用的电脑环境

下面是**实际研究电脑**的信息，不是最低配置，也不代表所有同类 Mac 均已兼容。

| 项目 | 实测环境 |
|---|---|
| 电脑 | MacBook Pro，机型标识 `Mac16,8` |
| 芯片／CPU | Apple M4 Pro，12 核 CPU：8 个性能核、4 个能效核 |
| 内存 | 24 GB |
| 架构 | `arm64`／Apple Silicon |
| macOS | 27.2，构建号 `26B5091g` |
| Shell | zsh |
| Python | 独立虚拟环境中的 3.12.14 |
| USB | PyUSB 1.3.1、libusb-package 1.0.30.0 |
| 数值／图像工具 | NumPy 2.5.4、SciPy 1.18.1、rawpy 0.27.1／LibRaw 0.22.1、Pillow 13.0.0 |
| 研究工具 | Capstone 5.0.6、pyelftools 0.32、Unicorn 2.1.4、Zig 0.13.0、Keystone 0.9.2 |
| 原生构建辅助 | CMake 3.31.10；Keystone 共享库由固定的官方源码编译为 arm64 |
| 元数据工具 | 固定源码提交的 ExifTool 13.59 |
| 相机 | 一台 Sony ILCE-7CR，相机版本界面为 2.01 |

公开记录不包含电脑序列号、UUID、主机名、用户名、个人绝对路径、相机序列号／
绑定摘要或照片原片。机器可读记录见 [validation/environment.json](validation/environment.json)。
本项目没有对 Intel Mac、Windows／Linux 相机访问、其他 macOS 版本或其他机身做
实机验证。

## 准备环境

下载解压或克隆本仓库，在终端进入仓库根目录。若要复现记录环境，使用 Python 3.12：

```sh
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python a7cr.py bootstrap
python a7cr.py doctor
```

`bootstrap` 通过 Git 获取 [upstream.lock.json](upstream.lock.json) 中固定提交的
上游源码。首次需要网络。若已有目录的提交不符，程序会停止，而不是重置该目录。
上游原始署名与许可留在本地检出目录；它们不会因此改成我们的许可。

这个命令不下载 Sony 官方固件包，也不下载 DCP 发布附件。已有固定提交的本地检出
可直接复用，不必再次获取。电脑需有 Git 与 Perl；原生研究构建还需对应构建工具。
虚拟环境和上游检出目录均被 Git 忽略。

### 只检查环境

```sh
python a7cr.py doctor
```

输出 Python、系统架构、部分依赖版本和上游提交状态。不会枚举 USB、读取硬件
序列号、进行相机认证、卸载磁盘或打开设备。

## 公开命令

### 识别已连接的相机

在相机选择**影像传输／MSC**，直接连接 Mac，然后运行：

```sh
python a7cr.py identify
```

仅列出 Sony USB 产品与接口描述符，不输出序列号，不进入服务模式。
本次观察到普通 A7CR 为 `054c:0e86`，服务身份为 `054c:0336`。
PID 本身不能作为机型确认依据，实际流程还核对产品和接口。

### 读取当前机身状态的备份

先在相机版本界面确认固件版本。两个目标目录必须都是新目录，彼此不同，且不能相互嵌套：

```sh
sudo .venv/bin/python a7cr.py backup \
  --firmware-version 2.01 \
  --workspace private/backups/camera-01-a \
  --backup-copy private/backups/camera-01-b
```

管理员授权在你自己的终端输入，不把密码作为程序参数。macOS 端先核对磁盘确实
属于这台 A7CR，再正常、非强制地卸载相机磁盘，并捕获该相机的 USB 接口。

USB 时序很重要：开始前选择 MSC。程序正在切换到服务模式时，**不要再次点击
相机的 USB／MSC 选择**；Mac 如出现“允许配件连接”，可允许。只有出现明确的
“读取已结束”提示后，才按提示重新选择 MSC。未知结果之后不会自动重复服务认证。

八个备份文件包括 AP／CP 组件、实时／已保存 Backup 快照，以及从快照中提取的
四个 CP 单元。此前一次冗余的直接 READ40 单元00发生超时，因此这里不再发送该
请求。两份文件都按字节核验，并设置本地私有权限。

备份代表**当前状态**，机身若已修改，备份也包含修改；不能据此声称是原厂备份。
同一块磁盘上的两个目录不能防范整块磁盘丢失，清单会报告这一点；条件允许时，
使用另一块物理存储作为第二目的地。保留完整私人备份。读取超时或服务状态未知时，
保留输出与任务，不要盲目重复运行。

### 在本地转换 DCP

原始文件由使用者根据
[上游 DCP 说明](https://github.com/QAQLeonard/a7c2-fl23-research/blob/b51688deecb56cd34fdd1f2948915cd6ea4e6736/docs/zh-CN/profiles.md)
自行获取。本项目不附带 DCP 或预计算 LUT。

优先使用实测的转换模型：

```sh
python a7cr.py fit-dcp /path/to/profile.dcp \
  --name "My Look" --slot 1 \
  --calibration /path/to/measured-model.json \
  --output private/fits/my-look-01
```

若只是明确接受上游单场景 A7C II 模型的暂定实验，可使用：

```sh
python a7cr.py fit-dcp /path/to/profile.dcp \
  --name "My Look" --slot 1 --use-upstream-model \
  --output private/fits/provisional-01
```

输出为 1,215 字节有符号7位修正表和本地报告，**不是可安装任务**。转换器只使用
DCP LookTable／tone 阶段，不是完整 Adobe RAW 显影器。上游单场景模型也不是
这台 A7CR 的实测标定；较低的合成拟合误差不等于实机色彩准确性。

报告包含暂定模型的中性灰高光检查，其数值不是 IRE，也不是传感器曝光百分比。
不要把删除模型显影曝光参数当成通用高光修复，这也会改变中灰亮度。

导入槽位要求**实际基础外观为 ST**。菜单中的基础外观选择器仍可编辑，并没有锁死。
这与使用自身处理记录的原生 FL2／FL3 是不同路径。拟合完成不能证明机身绑定、
运行中加载或实拍效果已经正确。

### 分析 RAW+JPEG 曝光序列

明确选择同名 `.ARW` 与 `.JPG` 文件对。工具直接读取输入，并新建输出目录，
不覆盖或修改原片：

```sh
python a7cr.py analyze-photos \
  --input /path/to/DCIM/100MSDCF \
  --stems DSC00001 DSC00002 DSC00003 \
  --output private/analysis/exposure-01
```

只请求预先列出的元数据标签，不请求 GPS 和序列号。输出包含本地元数据、RAW
达到上限的采样统计、JPEG 白色像素统计与缩略图。本地元数据仍可能包含原始文件
路径，分享前需检查。目前支持 2×2 Bayer RAW+JPEG，不支持仅 HEIF 输入，也不是
完整的色彩标定流程。

本次 A7CR 曝光测试见[验证与限制](docs/VALIDATION.zh-CN.md)：原生 FL2 在 ISO400、
F2、快门 1/400 至 1/3200 的四张照片中，RAW 饱和与 JPEG 纯白面积随减光下降。
这没有建立“白端被锁死”的结论，也没有“修好了曝光算法”的成果声明；该组照片
不用于验收六款导入 DCP 外观。

## 安装研究源码

使用 `offline/` 和 `device/` 前先读[研究流程](docs/WORKFLOW.zh-CN.md)及
[验证限制](docs/VALIDATION.zh-CN.md)。源码包含程序构建、原生交易模块、预检、
选中设置、名称资源、WBI、停止状态核对和重载后检查。

部分路径有意保留原研究任务名称，需要重新准备并审核自己的私人工作目录。
原始任务的私人清单、载荷和逐次终端启动脚本不随发布包提供。

流程把程序、名称、配方、WBI、完全断电、已加载 AP 检查与实拍验收分开。
不能因为后续名称读回超时，就重复此前已成功的 CP 写入；只允许根据证据确认的
特定阶段收尾。新鲜的无关设置与本机校准必须保留。完整实机还原尚未验证，
软件逆向恢复通过不能作为硬件恢复保证。

## 离线测试

```sh
python -m pip install -r requirements-research.txt
python tools/run_tests.py
python tools/audit_publication.py
```

本次公开主机测试：**127 项，其中 84 项通过、43 项跳过，0 失败／错误**。
私人机身集成样本刻意排除，跳过不算通过。该测试套件的设备协议调用均使用模拟，
不会连接相机。原生 CPU／系统调用模拟、历史读回和实机回报属于不同证据层级，
见 [validation/public-tests.json](validation/public-tests.json) 与验证说明。

原研究环境的部分 Unicorn ARM 模拟需要在进程沙箱外执行；这不代表相机授权，
也不能作为完整硬件模拟证明。

## 目录结构

```text
a7cr.py                 公开的主机／离线入口
tools/                  固定依赖、DCP拟合、照片分析、测试和发布检查
device/                 A7CR读取、macOS归属判断、研究交易与测试
offline/                来源分析、补丁／原生模块构建和检查
docs/                   中英文研究流程、验证与限制
licenses/               保留的上游软件许可
validation/             脱敏电脑环境与公开测试摘要
private/、research/     仅本地，Git忽略，不发布
```

## 许可与参与

对应软件代码使用 MIT，并保留上游署名。Sony 固件、抽取的原厂色彩／校准资产、
DCP/LUT 数据与个人照片不属于该授权范围，见 [NOTICE.md](NOTICE.md)。

反馈问题时提供机型／固件、系统版本与架构、命令、经过脱敏的失败阶段。未知结果
的原始日志在本地保留，不上传固件、机身备份、校准、标识或私人照片。
贡献须区分软件模拟、文件读回、实际加载与实拍证据。新固件／新机型需另行定位
与验证，修改机型限制或沿用偏移并不能构成适配。
