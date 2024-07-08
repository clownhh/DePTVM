package util

import (
	"bufio"
	"log"
	"os"
	"strings"
)

var config map[string]string = make(map[string]string, 2)
//创建了一个键类型为 string，值类型也为 string 的映射，并预先分配了一些空间（这里是2个键值对的空间）。

func ReadConfig() map[string]string {
	config = make(map[string]string)
	//readConnProperties()
	readConfig("config/conn.properties")
	return config
}

//读取拓扑配置文件，并将其内容解析为一个 map[string]string 类型的字典
func ReadTopologyConfig() map[string]string {
	config = make(map[string]string)
	//readTopologyProperties()
	readConfig("config/topology.properties")
	return config
}

/*
func readTopologyProperties() {
	readConfig("config/topology.properties")
}

func readConnProperties() {
	readConfig("config/conn.properties")
}
*/
func readConfig(filepath string) {
	file, err := os.Open(filepath)
	if err != nil {
		return
	}
	defer file.Close()   //确保文件在函数返回时被关闭的常见模式，即使函数因错误提前返回。这有助于防止文件句柄泄漏。

	scanner := bufio.NewScanner(file)    //用于创建一个新的扫描器（scanner），可以逐行读取文件内容。
	for scanner.Scan() {                    //逐行读取文件
		line := scanner.Text()          //用于获取当前行的文本
		s := strings.Split(line, "=")   //将字符串按等号 = 分割成键值对
		config[s[0]] = s[1]             //存储分离后的键值对
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
