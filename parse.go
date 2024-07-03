package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// 检查字符串是否为十六进制编码
func isHex(s string) bool {
	reHex := regexp.MustCompile(`^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$`)
	return reHex.MatchString(s)
}

// 解码Base64字符串
func base64Unarmor(s string) ([]byte, error) {
	reBase64 := regexp.MustCompile(`(?s)-----BEGIN [^-]+-----(.+?)-----END [^-]+-----|begin-base64[^\n]+\n(.+?)====|^(.+)$`)
	matches := reBase64.FindStringSubmatch(s)
	if matches != nil {
		for _, match := range matches[1:] {
			if match != "" {
				return base64.StdEncoding.DecodeString(strings.ReplaceAll(match, "\n", ""))
			}
		}
	}
	return nil, fmt.Errorf("invalid Base64 string")
}

func decodeString(str string) ([]byte, error) {
	var der []byte
	var err error

	if isHex(str) {
		der, err = hex.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex: %v", err)
		}
	} else if _, err := base64.StdEncoding.DecodeString(str); err == nil || strings.Contains(str, "BEGIN") {
		der, err = base64Unarmor(str)
		if err != nil {
			return nil, fmt.Errorf("error decoding base64: %v", err)
		}
	} else {
		der = []byte(str)
	}
	return der, nil
}

//func main() {
//	str := `YOUR_STRING_HERE` // 替换为你的字符串
//
//	der, err := decodeString(str)
//	if err != nil {
//		fmt.Println("Error:", err)
//		return
//	}
//
//	fmt.Printf("Decoded bytes: %x\n", der)
//}
