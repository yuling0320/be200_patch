# 构建与源码核对

发布DLL使用既有DevEco LLVM中的OHOS clang15.0.4、lld-link和llvm-lib构建，Python使用pefile2024.8.26。这里不捆绑编译器或华为原版程序。

`proxy.c`、`adapter_policy.h`、`win_min.h`、`build.py`和发布安装脚本保持与独立检查记录中的字节一致。测试程序只将本地个人路径改为test-input相对路径、将一个示例IPv4改为文档示例地址；不改变发布DLL。

## 构建

1. 在Windows x64准备Python和上述LLVM工具链。
2. 安装requirements.txt所列依赖。
3. 查看build.py中的LLVM目录，按本机环境设置；默认是DevEco Studio的工具目录。
4. 在src目录执行 `python build.py`。

构建只在src目录生成对象、导入库、DLL、清单和测试程序，不安装模块，不启动华为程序。build.py对本机系统IP Helper的313项导出作固定版本检查；系统不同可能直接停止。

CompatProbe.exe用于本地API透明转发、并发与规则测试。IdentityProbe.exe需要使用者自行在src/test-input中提供原版和修改版EXE测试副本，仅读取文件校验哈希，不执行它们。此仓库不提供这两份华为文件。

重新构建出的文件即使能编译，也不能直接沿用旧审核记录作已验证声明。应核对哈希、ABI和行为，重新验证后再考虑部署。src生成的manifest.json只反映构建，不替代patch目录中已验证发布的记录。
