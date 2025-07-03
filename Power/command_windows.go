//go:build windows

// Package Power 提供跨平台系统功能
package Power

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// Commander 命令执行器接口
type Commander interface {
	Exec(cmdStr string) (int, string, error)
}

// NewCommand 创建平台对应的命令执行器
func NewCommand() Commander {
	return &windowsCommand{}
}

// ConvertEncoding 编码转换函数
func ConvertEncoding(data []byte) string {
	if isGBK(data) {
		decoder := simplifiedchinese.GB18030.NewDecoder()
		result, _ := decoder.Bytes(data)
		return string(result)
	}
	return string(data)
}

func isGBK(data []byte) bool {
	length := len(data)
	for i := 0; i < length; {
		if data[i] <= 0x7f {
			i++
			continue
		} else {
			if i+1 < length && data[i] >= 0x81 &&
				data[i] <= 0xfe && data[i+1] >= 0x40 &&
				data[i+1] <= 0xfe && data[i+1] != 0x7f {
				i += 2
				continue
			}
			return false
		}
	}
	return true
}

type windowsCommand struct{}

func newWindowsCommand() Commander {
	return &windowsCommand{}
}

// RegisterService 注册Windows服务
//
//go:export RegisterService
func RegisterService(serviceName, exePath string) error {
	cmd := exec.Command("sc", "create", serviceName,
		"binPath=", exePath,
		"start=", "auto")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	cmd = exec.Command("sc", "description", serviceName,
		"NKN Trojan Client Service")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	_, err = cmd.CombinedOutput()
	return err
}

// UnregisterService 删除Windows服务
func UnregisterService(serviceName string) error {
	cmd := exec.Command("sc", "delete", serviceName)
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	_, err := cmd.CombinedOutput()
	return err
}

func (wc *windowsCommand) Exec(cmdStr string) (int, string, error) {
	// 处理带引号的参数
	args := []string{"/c"}
	if strings.Contains(cmdStr, "\"") {
		args = append(args, cmdStr)
	} else {
		args = append(args, strings.Fields(cmdStr)...)
	}

	cmd := exec.Command("cmd", args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		HideWindow: true,
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, "", fmt.Errorf("%v: %s", err, ConvertEncoding(out))
	}

	output := ConvertEncoding(out)
	return cmd.Process.Pid, output, nil
}
