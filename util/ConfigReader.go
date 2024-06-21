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
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		s := strings.Split(line, "=")
		config[s[0]] = s[1]
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
