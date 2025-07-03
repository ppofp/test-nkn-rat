package Power

/*
文件传输模块
功能：
1. 文件上传/下载
2. 文件分块传输
3. 文件校验
*/

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

const (
	chunkSize = 1024 * 1024 // 1MB分块
)

// FileMeta 文件元信息
type FileMeta struct {
	Name string
	Size int64
	MD5  string
}

// GetFileMD5 计算文件MD5
func GetFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// SplitFile 分块读取文件
func SplitFile(filePath string) ([][]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var chunks [][]byte
	buffer := make([]byte, chunkSize)

	for {
		bytesRead, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		chunk := make([]byte, bytesRead)
		copy(chunk, buffer[:bytesRead])
		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// SaveFile 保存文件
func SaveFile(filePath string, data []byte) error {
	// 创建目录
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

// AppendFile 追加文件内容
func AppendFile(filePath string, data []byte) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}
