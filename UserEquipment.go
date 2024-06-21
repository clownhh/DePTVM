package main

import (
	"NPTM/proto"
	"NPTM/util"
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"

	"go.dedis.ch/kyber/v4/suites"
)

//go run UserEquipment.go
//part code of NE

//define part
type UserEquipment struct {
	//net config
	AccessPointAddr *net.UDPAddr
	Socket          *net.UDPConn
	Status          int
	//crypto variables
	Suite            suites.Suite
	PrivateKey       kyber.Scalar
	PublicKey        kyber.Point
	OnetimePseudoNym kyber.Point
	G                kyber.Point
}

//status

// configuration
const UE_CONFIGURATION = 0

// connected with OA
const UE_CONNECTED = 1

//function part
var userEquipment *UserEquipment

/**/
func Handle_UE(buf []byte, addr *net.UDPAddr, tmpUserEquipment *UserEquipment, n int) {
	//decode the event 处理函数
	/*1.buf []byte:
	类型是 []byte，表示一个字节切片（slice）。通常用于存储二进制数据或字节流。
 	2.addr *net.UDPAddr:
	类型是 *net.UDPAddr，表示一个指向 net.UDPAddr 类型的指针。net.UDPAddr 是 Go 标准库中的一个结构体，表示一个 UDP 地址。
	3.tmpUserEquipment *UserEquipment:
	类型是 *UserEquipment，表示一个指向 UserEquipment 类型的指针。UserEquipment 是一个用户自定义的类型，通常是一个结构体（struct）。 
	4.n int:
	类型是 int，表示一个整数。
	*/

	userEquipment = tmpUserEquipment
	event := &proto.Event{}
	/*1.创建一个 proto.Event 类型的新实例：
	proto.Event{} 通过结构体字面量语法创建了一个 proto.Event 类型的新实例，并将其所有字段初始化为该类型的零值。例如，整数字段会初始化为 0，字符串字段会初始化为空字符串，指针字段会初始化为 nil，等等。
	2.取得新实例的指针：
	&proto.Event{} 返回新创建的 proto.Event 实例的指针。即，它创建了一个 proto.Event 类型的实例，并返回指向该实例的指针。
	3.将指针赋值给变量 event：
	event := &proto.Event{} 使用短变量声明语法（:=）将新创建的 proto.Event 实例的指针赋值给变量 event。event 的类型是 *proto.Event，即 proto.Event 类型的指针。
	*/
	
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	/*1.创建一个新的字节读取器：
	bytes.NewReader(buf[:n]) 创建了一个新的 bytes.Reader，它会从 buf 切片的前 n 个字节中读取数据。
	buf[:n] 是一个切片操作，从 buf 中取出前 n 个字节。
	2.创建一个新的 GOB 解码器：
	gob.NewDecoder(bytes.NewReader(buf[:n])) 使用前面创建的 bytes.Reader 实例创建了一个新的 gob.Decoder。gob.Decoder 用于解码 GOB 编码的二进制数据。
	3.解码数据到 event：
	.Decode(event) 调用解码器的 Decode 方法，将读取到的二进制数据解码到 event 变量中。
	event 通常是一个指针，指向要填充数据的结构体或其他类型的实例。
	4.错误处理：
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event) 将 Decode 方法返回的错误（如果有的话）赋值给 err 变量。解码过程中如果没有错误发生，err 会是 nil。
	*/
	
	util.CheckErr(err)
	/*util.CheckErr(err) 表示调用 util 包中的 CheckErr 函数，并将 err 作为参数传递给该函数。这通常用于处理错误。
	util.CheckErr 函数的定义和具体实现取决于 util 包的内容。一个常见的 CheckErr 函数可能会检查 err 是否为 nil，如果不为 nil，则处理该错误，例如打印错误信息并终止程序。
	*/
	
	switch event.EventType {
	case proto.UE_REGISTER_CONFIRMATION:
		handleRegisterConfirmation(userEquipment)
		break
	case proto.SYNC_REPMAP:
		handleSyncRepUE(event.Params, userEquipment)
		break
	default:
		fmt.Println("[UE] Unrecognized request!")
		break
	}
}

//init
func initUE(APAddr string) {
	//load AP's ip and port
	AccessPointAddr, err := net.ResolveUDPAddr("udp", APAddr)
	/*net.ResolveUDPAddr 函数用于将一个网络地址解析为 *net.UDPAddr 类型的地址。该函数解析提供的地址，并返回一个包含 IP 和端口信息的 net.UDPAddr 结构体指针。如果解析过程中发生错误，则返回一个错误。
 	net.ResolveUDPAddr 函数将一个网络地址字符串 APAddr 解析为 *net.UDPAddr 类型。
	第一个参数 "udp" 指定网络类型，表示这是一个 UDP 地址。
	第二个参数 APAddr 是一个字符串，表示要解析的地址，通常包含 IP 地址或主机名和端口号（例如 "192.168.1.1:8080" 或 "localhost:8080"）。
	*/
	
	util.CheckErr(err)
	//initlize suite
	suite := edwards25519.NewBlakeSHA256Ed25519()  // Use the edwards25519-curve
	//表示初始化一个新的加密套件，使用 Ed25519 椭圆曲线和 Blake2b 哈希函数进行操作。Ed25519 是一种基于椭圆曲线的数字签名算法，具有高安全性和高效性，Blake2b 是一种快速的加密哈希函数。
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	//生成一个随机的私钥（标量）
	A := suite.Point().Mul(a, nil)
	//使用私钥 a 和椭圆曲线的基点（也称为生成元）计算公钥 A。
	/*suite.Point():
	创建一个新的椭圆曲线点。在椭圆曲线密码学中，点通常表示公钥。
	Mul(a, nil):
	Mul 方法用于点乘操作。a 是一个标量（私钥），nil 表示使用椭圆曲线的基点（生成元）进行乘法运算。
	具体来说，这相当于计算 a * G，其中 G 是椭圆曲线的基点。
 	*/
	
	userEquipment = &UserEquipment{AccessPointAddr, nil, UE_CONFIGURATION, suite, a, A, suite.Point(), nil}
	//初始化一个 UserEquipment 结构体实例，并为其字段赋值。  //suite.Point() 创建了一个新的椭圆曲线点。
	fmt.Println("[UE] Parameter initialization is complete.")
	fmt.Println("[UE] My public key is ", userEquipment.PublicKey)
}

//register
func registerUE() {
	// set the parameters to register
	bytePublicKey, _ := userEquipment.PublicKey.MarshalBinary()
	// kyber.Point 接口的一个方法，用于将椭圆曲线点序列化为字节数组。这个方法在需要将点传输或存储时非常有用。
	params := map[string]interface{}{
		"public_key": bytePublicKey,
	}
	//声明、初始化并赋值。
	/*创建了一个 map[string]interface{} 类型的变量 params，其中包含一个键值对，将序列化后的公钥（字节数组）存储在 public_key 键下。
 	map[string]interface{} 是一种灵活的方式来存储不同类型的值，因为 interface{} 可以表示任何类型。
	*/
	
	event := &proto.Event{proto.UE_REGISTER_APSIDE, params}
	//创建一个包含 proto.UE_REGISTER_APSIDE 和 params 的 proto.Event 结构体实例。
	util.SendToAccessPoint(userEquipment.Socket, util.Encode(event))
}

// print out register success info
func handleRegisterConfirmation(userEquipment *UserEquipment) {
	//print out the register success info
	fmt.Println("[UE] Register success !")
	userEquipment.Status = UE_CONNECTED

}

//get UE's one-time pseudonym and g
func handleSyncRepUE(params map[string]interface{}, userEquipment *UserEquipment) {
	//set one-time pseudonym and g
	g := userEquipment.Suite.Point()
	// deserialize g and calculate nym
	g.UnmarshalBinary(params["g"].([]byte))
	nym := userEquipment.Suite.Point().Mul(userEquipment.PrivateKey, g)
	//set UE'S parameters
	userEquipment.G = g
	userEquipment.OnetimePseudoNym = nym

	//print out the UE's nym
	fmt.Println("[UE] One-Time pseudonym for this round is :", userEquipment.OnetimePseudoNym)
}

func startUEListener() {
	fmt.Println("[UE] UserEquiment Listener started...")
	buf := make([]byte, 4096)
	for {
		n, addr, err := userEquipment.Socket.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		go Handle_UE(buf, addr, userEquipment, n)
	}
}

//main function
func main() {
	//get AP's address

	fmt.Println("[UE] User equiment started!")
	fmt.Print("[UE] Please enter the IP address of the access point: ")
	reader := bufio.NewReader(os.Stdin)
	ipdata, _, err := reader.ReadLine()
	if err == nil {
		fmt.Println("[UE] Enter success!")
	}
	APAddr := string(ipdata)

	//initial params and network configurations
	initUE(APAddr)

	conn, err := net.DialUDP("udp", nil, userEquipment.AccessPointAddr)
	util.CheckErr(err)

	//set socket
	userEquipment.Socket = conn
	//start listener
	go startUEListener()
	time.Sleep(1.0 * time.Second)

	registerUE()
	fmt.Println("[UE] Wait for register confirmation.")
	for userEquipment.Status != UE_CONNECTED {
		//wait for UE register success
	}

	// read command and process
	fmt.Println("[UE] Enter your command.")

Loop:
	for {
		fmt.Print("cmd >> ")
		data, _, _ := reader.ReadLine()
		command := string(data)
		commands := strings.Split(command, " ")
		switch commands[0] {
		case "exit":
			break Loop
		default:
			fmt.Println("[UE] Hello!")
		}

	}

	conn.Close()
	fmt.Println("[UE] Exit system...")
}
