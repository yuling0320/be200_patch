# be200_patch

华为电脑管家 **14.0.7.310(C233)** 的 Intel **BE200** Wi-Fi Direct 投屏兼容模块，Windows x64。

已在一台 Windows 11 25H2、BE200 驱动24.20.0.4与HarmonyOS 7手机的组合上确认手机画面和鼠标操作正常。没有进行长时间压力测试，不保证其他电脑、系统更新或软件版本同样适用。

## 下载与使用

到 [Releases](https://github.com/yuling0320/be200_patch/releases/latest) 下载 **be200_patch.zip**，也可下载 [仓库中的精简包](downloads/be200_patch.zip)。解压后先阅读 [安装说明](安装说明.md)。

ZIP 只包含7个运行与说明文件，不需要完整逆向研究目录、Python、Node.js或编译器。原版华为电脑管家安装包及其他基础安装辅助工具不在本仓库内，需要使用者自行准备。

1. 先安装相同版本电脑管家到默认目录。
2. 解压精简包，在管理员 Windows PowerShell 中先运行 `-ValidateOnly` 检查，通过后再 `-Mode Apply`。
3. 安装后保存工作并正常重启电脑，刷新后台协同注册。
4. 手机 WLAN 关闭10秒再打开，保持解锁并连接多屏协同。

## 修复内容

原服务用适配器描述识别Wi-Fi Direct虚拟接口；BE200 WiFiCx提供的描述不在旧规则中，导致无法获取组接口MAC。

本模块作为电脑管家应用目录的IP Helper代理，只在原版连接服务的指定查询中，将匹配原注册表IPv4的唯一BE200编号虚拟接口描述转换为旧程序认识的名称。接口MAC、IP、索引等字段保持原值，其他函数转发到系统DLL。

- 保留原版 `HiConnectivityService.exe` 和华为数字签名、组件间验签。
- 不修改网卡驱动、系统DLL、注册表或防火墙规则。
- 本模块是**未签名DLL**，会随华为服务以SYSTEM权限运行；其他从同一应用目录启动的进程也可能加载代理代码。
- 只安装到 `C:\Program Files\Huawei\PCManager\iphlpapi.dll`，不放入Windows系统目录。

早期直接修改EXE的方案因IPC签名校验失败已撤回，不在发布包中。

## 版本约束

| 项目 | 已验证版本 |
| --- | --- |
| Windows | Windows 11 Pro 25H2，26200.9457，x64 |
| 电脑管家 | 14.0.7.310(C233) |
| 网卡驱动 | Intel BE200 24.20.0.4 |
| 手机系统 | HarmonyOS 7 |

安装脚本绑定原版服务和系统IP Helper的SHA256。Windows或电脑管家更新后检查可能停止，需要重新评估；不能修改清单哈希来跳过检查。

## 校验与撤回

模块SHA256：

```text
73e9979e77b61ea31727222b346c51c6d4c51d5b9a3877e91075f431d67678ae
```

在精简包目录的管理员PowerShell中运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-BE200Proxy.ps1 -Mode Rollback
```

然后正常重启电脑。详细结果会写入同目录 `operation-*.json`。

## 源码与验证

在同一工具链和系统DLL环境，从本仓库源码重新构建的DLL与发布文件SHA256完全一致。

- `src/`：代理源码、构建脚本和本地测试程序源码；见 [构建说明](src/README.md)。
- `patch/`：实际发布的DLL、安装脚本和验证记录。
- `downloads/`：可直接下载的7文件精简ZIP。
- `SHA256SUMS.txt`：ZIP及解压后DLL的校验值。

本项目由AI辅助完成分析、实现和检查。验证记录包括313项导出核对、312个转发函数的624次异常展开检查、并发转发测试、适配器数据重放与一次实际手机连接验收；这些记录不等同于第三方安全认证。
