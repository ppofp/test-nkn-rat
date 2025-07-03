//go:build linux

package Power

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Commander 命令执行器接口
type Commander interface {
	Exec(cmdStr string) (int, string, error)
}

// RegisterService 注册Linux系统服务
func RegisterService(serviceName, exePath string) error {
	serviceFile := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	content := fmt.Sprintf(`[Unit]
Description=NKN Trojan Client Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
User=root

[Install]
WantedBy=multi-user.target`, exePath)

	err := os.WriteFile(serviceFile, []byte(content), 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("systemctl", "enable", serviceName)
	return cmd.Run()
}

// UnregisterService 删除Linux系统服务
func UnregisterService(serviceName string) error {
	cmd := exec.Command("systemctl", "disable", serviceName)
	if err := cmd.Run(); err != nil {
		return err
	}

	serviceFile := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	return os.Remove(serviceFile)
}

type linuxCommand struct{}

func (lc *linuxCommand) Exec(cmdStr string) (int, string, error) {
	// 处理带引号的参数
	var cmd *exec.Cmd
	if strings.Contains(cmdStr, "\"") {
		cmd = exec.Command("bash", "-c", cmdStr)
	} else {
		parts := strings.Fields(cmdStr)
		if len(parts) == 0 {
			return 0, "", fmt.Errorf("empty command")
		}
		cmd = exec.Command(parts[0], parts[1:]...)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, "", fmt.Errorf("%v: %s", err, string(out))
	}
	return cmd.Process.Pid, string(out), nil
}

// NewCommand 创建平台对应的命令执行器
func NewCommand() Commander {
	return &linuxCommand{}
}
