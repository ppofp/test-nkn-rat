package Power

/*
AES加密模块
功能：
1. AES-CBC加密/解密
2. PKCS5填充
3. 错误处理和恢复
*/

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"log"
	"runtime"
)

const (
	// 默认初始化向量
	ivaes = "4EF9b11482B4ccaf"
)

func PKCS5Padding(plainText []byte, blockSize int) []byte {
	/*
		PKCS5填充
		参数:
		plainText: 明文
		blockSize: 块大小
		返回: 填充后的字节数组
	*/
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}

func PKCS5UnPadding(plainText []byte) ([]byte, error) {
	/*
		PKCS5去填充
		参数:
		plainText: 填充后的密文
		返回: 去填充后的明文和错误
	*/
	length := len(plainText)
	number := int(plainText[length-1])
	if number > length {
		return nil, nil
	}
	return plainText[:length-number], nil
}

func init() {
	log.SetFlags(log.Ldate | log.Lshortfile)
}

func AesCbcEncrypt(plainText, key []byte, ivAes ...byte) ([]byte, error) {
	/*
		AES-CBC加密
		参数:
		plainText: 明文
		key: 密钥(16/24/32字节)
		ivAes: 可选初始化向量
		返回: 密文和错误
	*/
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	var iv []byte
	if len(ivAes) != 0 {
		if len(ivAes) != 16 {
			return nil, nil //, ErrIvAes
		} else {
			iv = ivAes
		}
	} else {
		iv = []byte(ivaes)
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return cipherText, nil
}

func AesCbcDecrypt(cipherText, key []byte, ivAes ...byte) ([]byte, error) {
	/*
		AES-CBC解密
		参数:
		cipherText: 密文
		key: 密钥(16/24/32字节)
		ivAes: 可选初始化向量
		返回: 明文和错误
	*/
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, nil //, ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key or text is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	var iv []byte
	if len(ivAes) != 0 {
		if len(ivAes) != 16 {
			return nil, nil
		} else {
			iv = ivAes
		}
	} else {
		iv = []byte(ivaes)
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	paddingText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(paddingText, cipherText)

	plainText, err := PKCS5UnPadding(paddingText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
