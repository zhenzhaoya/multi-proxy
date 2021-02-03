package utils

import (
	"bufio"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"
)

func GetRandNum(min int, max int) int {
	if max <= min {
		return min
	}
	rand.Seed(time.Now().UnixNano())
	var i int = rand.Intn(max-min) + min
	return i
}
func GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}
func GetFileLines(path string) []string {
	f, err := ioutil.ReadFile(path)
	if err == nil {
		return strings.Split(string(f), "\n")
	}
	return nil
}
func ArrContains(arr []string, value string) bool {
	for k := range arr {
		if arr[k] == value {
			return true
		}
	}
	return false
}
func StrContains(value string, arr []string) bool {
	for k := range arr {
		if !strings.Contains(value, arr[k]) {
			return false
		}
	}
	return true
}
func StrContainsOr(value string, arr []string) bool {
	for k := range arr {
		if strings.Contains(value, arr[k]) {
			return true
		}
	}
	return false
}
func ArrContainsOr(arr []string, values []string) bool {
	for i := range arr {
		for j := range values {
			if arr[i] == values[j] {
				return true
			}
		}
	}
	return false
}
func Trim(str string) string {
	return strings.Trim(str, " ")
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
func SaveFile(path string, content string) error {
	mode := os.O_CREATE
	if PathExists(path) {
		mode = os.O_TRUNC
	}
	file, err := os.OpenFile(path, os.O_WRONLY|mode, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	writer.WriteString(content)
	writer.Flush()
	return nil
}
