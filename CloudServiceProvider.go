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
	"sync"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

type CloudServiceProvider struct {
	//local address
	LocalAdress *net.UDPAddr
	//sokect
	Socket *net.UDPConn

	// crypto variables
	Suite      suites.Suite
	PrivateKey kyber.Scalar
	PublicKey  kyber.Point
	G          kyber.Point

	OAList []*net.UDPAddr
	//Stored OA's public key&&addr
	OAKeyList map[string]kyber.Point
	APList    []*net.UDPAddr
	//Stored AP's public key&&addr
	APKeyList map[string]kyber.Point
	//trust value set
	Records []util.Record
}

var cloudServiceProvider *CloudServiceProvider

var memoryIndex int = 0
var OANum int = 0

//var APNum int = 0

var wait = sync.WaitGroup{}
/*sync.WaitGroup 是一个计数器，用来等待一组并发操作完成。
可以通过 Add 方法增加计数，通过 Done 方法减少计数，通过 Wait 方法阻塞，直到计数器归零。
*/

//the times of data sharing cycle
//======================3 Times================

const times = 3

func (c *CloudServiceProvider) AddOA(addr *net.UDPAddr, key kyber.Point) {
	// delete the OA who has same pub key
	for a, k := range c.OAKeyList {
		if k == key {
			delete(c.OAKeyList, a)
			break
		}
	}

	c.OAKeyList[addr.String()] = key
	c.OAList = append(c.OAList, addr)
}

func (c *CloudServiceProvider) AddAP(addr *net.UDPAddr, key kyber.Point) {
	// delete the AP who has same pub key
	for a, k := range c.APKeyList {
		if k == key {
			delete(c.APKeyList, a)
			break
		}
	}

	c.APKeyList[addr.String()] = key
	c.APList = append(c.APList, addr)
}

func Handle_CSP(buf []byte, addr *net.UDPAddr, tmpCSP *CloudServiceProvider, n int) {
	cloudServiceProvider = tmpCSP
	event := &proto.Event{}
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	util.CheckErr(err)

	switch event.EventType {
	case proto.AP_REGISTER:
		handleAPRegister(event.Params, addr)
		break
	case proto.OA_REGISTER_CSP:
		handleOARegister(event.Params, addr)
		break
	case proto.DATA_COLLECTION_AP:
		handleDataCollection_AP_Side(event.Params, addr)
		break
	case proto.DATA_COLLECTION_OA:
		handelDataCollection_OA_Side(event.Params, addr)
		break
	default:
		fmt.Println("[CSP] Unrecognized request...")
		break
	}
}

func handleAPRegister(params map[string]interface{}, addr *net.UDPAddr) {
	publicKey := cloudServiceProvider.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	cloudServiceProvider.AddAP(addr, publicKey)
	fmt.Println("[CSP] Receive the registration info from AccessPoint: ", addr)
	// set the parameters to register
	pm := map[string]interface{}{
		"reply": true,
	}
	event := &proto.Event{proto.AP_REGISTER_REPLY_CSP, pm}
	util.Send(cloudServiceProvider.Socket, addr, util.Encode(event))
}

func handleOARegister(params map[string]interface{}, addr *net.UDPAddr) {
	publicKey := cloudServiceProvider.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	cloudServiceProvider.AddOA(addr, publicKey)
	fmt.Println("[CSP] Receive the registration info from OperatorAgent: ", addr)
	bytePublickey, _ := cloudServiceProvider.PublicKey.MarshalBinary()

	pm := map[string]interface{}{
		"reply":      true,
		"public_key": bytePublickey,
	}
	event := &proto.Event{proto.OA_REGISTER_REPLY_CSP, pm}
	util.Send(cloudServiceProvider.Socket, addr, util.Encode(event))
}

func handleDataCollection_AP_Side(params map[string]interface{}, addr *net.UDPAddr) {
	Nym := cloudServiceProvider.Suite.Point()

	if ok, _ := params["Start"].(bool); ok {
		//ok, _ := params["Start"].(bool) 是一个短变量声明，其中 _ 用于忽略类型断言返回的具体值，而 ok 是一个布尔值，表示类型断言是否成功。
		fmt.Println("[CSP] Recieve the trust value related data from AccessPoint:", addr)

	}
	//verify the signature and store the records to local records
	Nym.UnmarshalBinary(params["Nym"].([]byte))
	Data := params["Data"].([]float64)
	record := util.Record{Nym, Data}
	//tmpRecord := util.ByteToRecord(params["Record"].([]byte))
	SignRe, _ := params["SignRe"].([]byte)
	err := util.SchnorrVerify(cloudServiceProvider.Suite, util.ToByteRecord(record),
		cloudServiceProvider.APKeyList[addr.String()], SignRe)
	util.CheckErr(err)
	if err == nil {
		//fmt.Println("[CSP] The sign of AccessPoint verify success!", srcAddr)
		cloudServiceProvider.Records = append(cloudServiceProvider.Records, record)
		//fmt.Println("[CSP] The records has been stored to local storage...")
	} else {
		fmt.Println("[CSP] The sign of AccessPoint verify failed!", addr)
	}

	if done, _ := params["Done"].(bool); done == true {
		//APNum++
		fmt.Println("[CSP] Data collection over from AccessPoint:", addr)
	}
}

//SEND ONE RECORD ONE TIME
//When recieve all AP's new data and all OA's data collection request,send data to OAs
func handelDataCollection_OA_Side(params map[string]interface{}, addr *net.UDPAddr) {

	if ok, _ := params["Require"].(bool); ok == true {
		if OANum <= len(cloudServiceProvider.OAList) {
			fmt.Println("[CSP] The data collection request from the OA is received.:", addr)
			OANum++
		} else {
			fmt.Println("[CSP] Some OA's data collection request wrong!")
		}

	} else {
		fmt.Println("[CSP] Data collection request confirmation failed!")
	}
}

func dataCollectionToOA() {
	//send one record one time
	fmt.Println("[CSP] Send the records to OperatorAgents.")
	size := len(cloudServiceProvider.Records)
	for i := memoryIndex; i < size; i++ {
		byteRecord := util.ToByteRecord(cloudServiceProvider.Records[i])
		SignRe := util.SchnorrSign(cloudServiceProvider.Suite, random.New(),
			byteRecord, cloudServiceProvider.PrivateKey)
		var start bool = false
		var done bool = false
		
		
		fmt.Println(cloudServiceProvider.Records[i])
		//set the start and done flag
		if i == 0 {
			start = true
		} else if i == size-1 {
			done = true
		}
		byteNym, _ := cloudServiceProvider.Records[i].Nym.MarshalBinary()
		pm := map[string]interface{}{
			"Start":  start,
			"Nym":    byteNym,
			"Data":   cloudServiceProvider.Records[i].Data,
			"SignRe": SignRe,
			"Done":   done,
		}

		event := &proto.Event{proto.DATA_COLLECTION_OA, pm}

		for _, OAAddr := range cloudServiceProvider.OAList {
			wait.Add(1)    //将 sync.WaitGroup 的计数器加 1。这个操作确保 WaitGroup 知道有一个新的 goroutine 需要等待。
			go func(OAAddr *net.UDPAddr) {
				defer wait.Done()     //确保 goroutine 完成时，将 WaitGroup 的计数器减 1。这是为了确保即使函数内部发生了错误，Done 也会被调用，避免程序死锁。
				util.Send(cloudServiceProvider.Socket, OAAddr, util.Encode(event))
			}(OAAddr)
		}
		wait.Wait()    //阻塞执行，直到 WaitGroup 的计数器减为零。
		//If each piece of trust data is sent without interval, packet corruption will occur, so the interval is 1 microsecond
		time.Sleep(1.0 * time.Millisecond)

	}
	memoryIndex = size
	fmt.Println("[CSP] Trust data has been sent.")
}

//监听然后处理
func startCSPListener() {
	fmt.Println("[CSP] CloudServiceProvider Listener started...")
	buf := make([]byte, 4096)
	for {
		n, addr, err := cloudServiceProvider.Socket.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		Handle_CSP(buf, addr, cloudServiceProvider, n)
	}
}

func initCSP() {
	config := util.ReadConfig()
	LocalAddr, err := net.ResolveUDPAddr("udp", config["csp_ip"]+":"+config["csp_port"])
	util.CheckErr(err)
	fmt.Println("[CSP] Local address :", LocalAddr)

	suite := edwards25519.NewBlakeSHA256Ed25519()  // Use the edwards25519-curve
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)

	cloudServiceProvider = &CloudServiceProvider{
		LocalAddr, nil,
		suite, a, A, nil,
		nil, make(map[string]kyber.Point), nil, make(map[string]kyber.Point), nil}
	fmt.Println("[CSP] Parameter initialization is complete.")
	fmt.Println("[CSP] My public key is ", cloudServiceProvider.PublicKey)
}

func main() {

	fmt.Println("[CSP] CloudServiceProvider started.")
	initCSP()
	conn, err := net.ListenUDP("udp", cloudServiceProvider.LocalAdress)
	util.CheckErr(err)
	cloudServiceProvider.Socket = conn
	go startCSPListener()
	// read command and process
	fmt.Println("[OA] Enter your command.(Type 'ok' to start cycle)")
	reader := bufio.NewReader(os.Stdin)
Loop:
	for {
		data, _, _ := reader.ReadLine()
		command := string(data)
		commands := strings.Split(command, " ")
		switch commands[0] {
		case "ok":
			break Loop
		default:
			fmt.Println("[OA] Hello!")
		}
	}
	size1 := len(cloudServiceProvider.OAList)
	//size2 := len(cloudServiceProvider.APList)
	fmt.Println()
	//start the cycle
	for i := 0; i < times; i++ {
		//go check()
		for !(OANum == size1) {
			time.Sleep(1.0 * time.Millisecond)
		}
		OANum = 0
		//APNum = 0
		dataCollectionToOA()

	}

	fmt.Println("[CSP] Exit system...")
	//cloudServiceProvider.Socket.Close()
}
