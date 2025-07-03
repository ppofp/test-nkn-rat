# Go-NKN-Trojan 远程控制工具

## 功能特性
- 基于NKN的P2P通信架构
- 跨平台支持(Windows/Linux)
- 支持多客户端管理
- 文件上传/下载
- 命令执行(支持cmd/powershell/bash)
- SOCKS5代理
- 服务自启动
- 心跳检测

## 使用说明

### 服务端启动
```bash
# 生成新seed
./Server -g new

# 使用已有seed启动
./Server -g [your_seed]
```

### 客户端管理
1. 查看客户端列表：
```bash
list
```

2. 切换到指定客户端：
```bash
use [客户端别名]
```

3. 执行命令(切换后可直接输入命令)：
```bash
[命令] [参数]
示例: 
cmd ipconfig
powershell Get-Process
bash ifconfig
```

### 文件传输
1. 上传文件到客户端：
```bash
upload [本地路径] [远程路径]
```

2. 从客户端下载文件：
```bash
download [远程路径] [本地路径]
```

### SOCKS5代理
```bash
socks5 [端口]
```

## 命令参考

| 命令       | 说明                     | 示例                     |
|------------|--------------------------|--------------------------|
| help       | 显示帮助信息             | help                     |
| list       | 显示客户端列表           | list                     |
| use        | 切换到指定客户端         | use pp-1                 |
| upload     | 上传文件                 | upload local.txt /tmp/   |
| download   | 下载文件                 | download /tmp/file.txt . |
| socks5     | 启动SOCKS5代理           | socks5 1080              |
| cmd        | 执行系统命令             | cmd ipconfig             |
| powershell | 执行PowerShell命令       | powershell Get-Process   |
| bash       | 执行Bash命令(Linux)      | bash ifconfig            |

## 项目结构
```
.
├── Client/          # 客户端代码
│   └── client_main.go
├── Power/           # 公共功能模块
│   ├── aes.go       # 加密模块
│   ├── command.go   # 命令执行
│   ├── file.go      # 文件传输  
│   └── ip.go        # 网络信息
└── Server/          # 服务端代码
    └── server_main.go
```

## 注意事项
1. 所有通信内容均加密传输
2. 文件传输会进行完整性校验
3. 兼容Go 1.24.2+版本

## 免责声明
本工具仅用于安全研究和合法授权测试，严禁用于非法用途。使用者需自行承担风险，作者不承担任何责任。
