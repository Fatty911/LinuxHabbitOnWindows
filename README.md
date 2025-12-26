[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)
# LinuxHabbitOnWindows
Use your favorite Linux commands to manage **Windows Native Resources**.   Forget `Get-NetTCPConnection`, just type `lsof`.  
这是一个为习惯 Linux 命令行的程序员设计的 PowerShell 模块。它不仅仅是别名（Alias），而是将 Linux 命令的逻辑**映射**到 Windows 的底层 API。

## 📄 License

This project is licensed under the **CC BY-NC-SA 4.0** License.
(Attribution-NonCommercial-ShareAlike 4.0 International)

✅ **You can**:
- Download and use this software for personal use.
- Modify the source code for personal use.
- Share with friends (with attribution).

❌ **You cannot**:
- Sell this software.
- Include this software in a commercial product.
- Distribute modified versions without the same license.


## ✨ Features

| Linux Command | Windows Native Mapping | Functionality |
| :--- | :--- | :--- |
| `lsof -i :port` | `Get-NetTCPConnection` + `Get-Process` | 查看端口占用进程 |
| `ufw status/allow` | `Get-NetFirewallRule` | 简易防火墙管理 |
| `free -h` | `CIM Win32_OperatingSystem` | 查看系统内存使用 |
| `systemctl start` | `Start-Service` | 管理 Windows 服务 |
| `pkill <name>` | `Stop-Process` | 按名称杀进程 |
| `touch <file>` | `New-Item` | 创建文件或更新时间戳 |
| `sudo` | `gsudo` (integration) | 提权运行 |




Copyright © 2025 XUE RUI

