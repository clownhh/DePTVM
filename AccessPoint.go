package main

import (
	"NPTM/proto"
	"NPTM/util"
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	_ "strings"
	_ "sync"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

const (
	//data and node 's scale && the number of cycle
	record_scale = 900
	//node_scale          = 2
	ListMaintenceNumber = 3
	//status
	AP_CONFIGURATION = 0
	AP_CONNECTED     = 2
	AP_COLLECTION    = 3
)

//var mu sync.Mutex

//part code of AP
////////////////////////////////////////////
//define part

type AccessPoint struct {
	// local address
	LocalAddr *net.UDPAddr
	// socket
	Socket *net.UDPConn
	// network topology for OA cluster
	OAList []*net.UDPAddr
	//the OA that deployed this AP
	OperatorAgentAddr *net.UDPAddr
	//CSP address
	CloudServiceProviderAddr *net.UDPAddr
	// initialize the AP status
	Status int

	// crypto variables
	Suite      suites.Suite
	PrivateKey kyber.Scalar
	PublicKey  kyber.Point
	G          kyber.Point

	// store UE address
	UEs map[string]*net.UDPAddr

	DecryptedTurstValueMap map[string]float64
	DecryptedKeysMap       map[string]kyber.Point
}

//get last OA
//为结构体a（AccessPoint）定义的方法
func (a *AccessPoint) GetLastOA() *net.UDPAddr {
	if len(a.OAList) == 0 {
		return nil
	}
	return a.OAList[len(a.OAList)-1]
}

//get first OA

func (a *AccessPoint) GetFirstOA() *net.UDPAddr {
	if len(a.OAList) == 0 {
		return nil
	}
	return a.OAList[0]
}

//add new userEquipment

func (a *AccessPoint) AddUE(key kyber.Point, val *net.UDPAddr) {
	// delete the client who has same ip address
	for k, v := range a.UEs {
		//用于迭代一个集合（如数组、切片、映射或通道）的常用语法。k 表示映射中的键，v 表示映射中的值
		if v.String() == val.String() {
			delete(a.UEs, k)
			break
		}
	}

	a.UEs[key.String()] = val
}

//add OA

func (a *AccessPoint) AddOA(addr *net.UDPAddr) {
	a.OAList = append(a.OAList, addr)
}

//add into decrypted TV map
func (a *AccessPoint) AddIntoDecryptedTVMap(key kyber.Point, val float64) {
	keyStr := key.String()
	a.DecryptedKeysMap[keyStr] = key
	a.DecryptedTurstValueMap[keyStr] = val
}

///////////////////////////////////////////////
//Handle function part
//如果你在函数外部（即在任何函数或方法之外）使用 var 声明一个变量，那么这个变量就是全局的，它可以在整个包（package）中被访问。
var accessPoint *AccessPoint
var srcAddr *net.UDPAddr

func Handle_AP(buf []byte, addr *net.UDPAddr, tmpAccessPoint *AccessPoint, n int) {
	accessPoint = tmpAccessPoint
	srcAddr = addr
	//decode the event
	event := &proto.Event{}
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	util.CheckErr(err)
	switch event.EventType {
	case proto.AP_REGISTER_REPLY_OA:
		handleAPRegisterReply_OA(event.Params, addr)
		break
	case proto.AP_REGISTER_REPLY_CSP:
		handleAPRegisterReply_CSP(event.Params, addr)
		break
	case proto.UE_REGISTER_APSIDE:
		handleUERegisterAPSide(event.Params)
		break
	case proto.UE_REGISTER_OASIDE:
		handleUERegisterOASide_AP(event.Params)
		break
	case proto.SYNC_REPMAP:
		handleSyncRepAP(event.Params)
		break
	default:
		fmt.Println("[AP] Unrecognized request...")
		break
	}
}

func handleUERegisterAPSide(params map[string]interface{}) {
	//get UE's public key
	publicKey := accessPoint.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	accessPoint.AddUE(publicKey, srcAddr)

	firstOA := accessPoint.GetFirstOA()

	pm := map[string]interface{}{
		"public_key": params["public_key"],
		"UEAddr":     srcAddr.String(),
		"UpperAP":    accessPoint.LocalAddr.String(),
	}

	event := &proto.Event{proto.UE_REGISTER_OASIDE, pm}
	fmt.Println("[AP] Send the UE's register info to OperatorAgent.")
	//send to first OA
	util.Send(accessPoint.Socket, firstOA, util.Encode(event))

}

func handleUERegisterOASide_AP(params map[string]interface{}) {
	var publicKey = accessPoint.Suite.Point()
	bytePublicKey := params["public_key"].([]byte)
	publicKey.UnmarshalBinary(bytePublicKey)

	UEAddrStr := params["UEAddr"].(string)
	addr, err := net.ResolveUDPAddr("udp", UEAddrStr)
	util.CheckErr(err)
	pm := map[string]interface{}{}
	event := &proto.Event{proto.UE_REGISTER_CONFIRMATION, pm}
	fmt.Println("[AP] Send the register info to UserEqiupment:", addr)
	util.Send(accessPoint.Socket, addr, util.Encode(event))
}

func handleAPRegisterReply_OA(params map[string]interface{}, addr *net.UDPAddr) {

	reply := params["reply"].(bool)

	if reply {
		accessPoint.Status++
		fmt.Println("[AP] Register success to OA:", addr)
	}

}

func handleAPRegisterReply_CSP(params map[string]interface{}, addr *net.UDPAddr) {
	reply := params["reply"].(bool)
	if reply {
		accessPoint.Status++
		fmt.Println("[AP] Register success to CSP:", addr)
	}
}

func handleSyncRepAP(params map[string]interface{}) {

	// This event is triggered when server finishes forward shuffle

	var g = accessPoint.Suite.Point()
	byteG := params["g"].([]byte)
	err := g.UnmarshalBinary(byteG)
	util.CheckErr(err)

	//construct Decrypted reputation map
	keyList := util.ProtobufDecodePointList(params["nyms"].([]byte))
	valList := params["vals"].([]float64)
	accessPoint.DecryptedTurstValueMap = make(map[string]float64)
	accessPoint.DecryptedKeysMap = make(map[string]kyber.Point)

	fmt.Println("[AP] Recieve the new reputation list.")
	for i := 0; i < len(keyList); i++ {
		accessPoint.AddIntoDecryptedTVMap(keyList[i], valList[i])
	}

	// distribute g and hash table of ids to user
	pm := map[string]interface{}{
		"g": params["g"].([]byte),
	}

	event := &proto.Event{proto.SYNC_REPMAP, pm}
	for _, UEAddr := range accessPoint.UEs {
		util.Send(accessPoint.Socket, UEAddr, util.Encode(event))
	}
	// set controller's new g
	accessPoint.G = g
	//allow ap to share data to CSP
	accessPoint.Status = AP_COLLECTION

}

/////////////////////////////////   更新网络拓扑
func updateTopology() {
	TopologyConfig := util.ReadTopologyConfig()
	list := util.SortMap(TopologyConfig)

	for _, v := range list {
		addr, err := net.ResolveUDPAddr("udp", v)
		util.CheckErr(err)
		accessPoint.OAList = append(accessPoint.OAList, addr)
	}

	fmt.Println("[AP] The OA topology list is updated!")
	fmt.Println("[AP] OA topology list:", accessPoint.OAList)
}

//initialize accesspoint
func initAP(LocalAddr *net.UDPAddr, Socket *net.UDPConn, OAAddr *net.UDPAddr, CSPAddr *net.UDPAddr) {

	suite := edwards25519.NewBlakeSHA256Ed25519()  // Use the edwards25519-curve
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)

	accessPoint = &AccessPoint{
		LocalAddr, Socket, nil, OAAddr, CSPAddr, AP_CONFIGURATION,
		suite, a, A, nil,
		make(map[string]*net.UDPAddr),
		make(map[string]float64), make(map[string]kyber.Point)}

	fmt.Println("[AP] Parameter initialization is complete.")
	fmt.Println("[AP] My public key is ", accessPoint.PublicKey)

}

func registerAP() {

	// set the parameters to register
	bytePublicKey, _ := accessPoint.PublicKey.MarshalBinary()
	params := map[string]interface{}{
		"public_key": bytePublicKey,
	}
	event := &proto.Event{proto.AP_REGISTER, params}
	//register to OA
	util.Send(accessPoint.Socket, accessPoint.OperatorAgentAddr, util.Encode(event))
	time.Sleep(1.0 * time.Millisecond)
	//register to CSP
	util.Send(accessPoint.Socket, accessPoint.CloudServiceProviderAddr, util.Encode(event))
}

//持续监听，并调用处理函数
func startAPListener() {
	fmt.Println("[AP] AccessPoint listener started...")
	buf := make([]byte, 4096)
	for {
		n, addr, err := accessPoint.Socket.ReadFromUDP(buf)
		util.CheckErr(err)
		go Handle_AP(buf, addr, accessPoint, n)
	}
}

func dataCollectionToCSP(localPort uint) {
	//read the csv and add the nym to the head, which is NE's behavior records   ?

	//get the data
	var Records = make([]util.Record, record_scale)
	//创建了一个长度为 record_scale 的切片，其中每个元素的类型是 util.Record。
	var opencast *os.File = nil
	//os.File 是 Go 标准库 os 包中的一个结构体，表示一个打开的文件对象。
	var err error = nil
	//fmt.Println(localPort)
	// support different dataset to different AP (simulate the dataset collected from UE)
	switch localPort {
	case 8000: opencast, err = os.Open("./datasets/dataset1.csv")
	case 8001: opencast, err = os.Open("./datasets/dataset2.csv")
	case 8002: opencast, err = os.Open("./datasets/dataset3.csv")
	case 8003: opencast, err = os.Open("./datasets/dataset4.csv")
	default: opencast, err = os.Open("./datasets/dataset-notime.csv")
	}
	
	if err != nil {
		fmt.Println("[AP] Dataset open failed!")
	}

	ReadCsv := csv.NewReader(opencast)

	//Get rid of the first row
	read, err := ReadCsv.Read()
	util.CheckErr(err)
	// fmt.Println(read)

	node_scale := len(accessPoint.DecryptedTurstValueMap)


	for i := 0; i < record_scale; i++ {
		//read one row
		read, err = ReadCsv.Read()
		util.CheckErr(err)
		//if read success,get the data to records
		for j := 0; j < len(read)-1; j++ {
			tempdata, _ := strconv.ParseFloat(read[j], 64)
			/*strconv 是 Go 标准库中的一个包，用于提供字符串与基本数据类型之间的转换功能。
			ParseFloat 是 strconv 包中的一个函数，用于将字符串转换为浮点数。
   			64 是转换精度参数，表示将字符串转换为 float64 类型的浮点数。
			*/
			if math.IsInf(tempdata, 0) || math.IsNaN(tempdata) {
				tempdata = 0.0
				//检查浮点数 tempdata 是否为正无穷、负无穷或 NaN（Not a Number），如果是，则将其重置为 0.0。
			}
			Records[i].Data = append(Records[i].Data, tempdata)
		}
	}
	opencast.Close()

	//get the nym from NElist
	i := 0
	for j := 0; j < record_scale/node_scale; j++ {

		for _, nym := range accessPoint.DecryptedKeysMap {
			Records[i].Nym = nym
			i++
		}

	}

	fmt.Println("[AP] Send the records to Cloud Service Provider...")

	//send one data one time
	for i = 0; i < record_scale; i++ {
		//sign the Record
		byteRecord := util.ToByteRecord(Records[i])
		SignRe := util.SchnorrSign(accessPoint.Suite, random.New(),
			byteRecord, accessPoint.PrivateKey)
		//mu.Lock()
		var start bool = false
		var done bool = false
		//set the start and done flag
		if i == 0 {
			start = true
		} else if i == record_scale-1 {
			done = true
		}

		byteNym, _ := Records[i].Nym.MarshalBinary()
		pm := map[string]interface{}{
			"Start":  start,
			"Nym":    byteNym,
			"Data":   Records[i].Data,
			"SignRe": SignRe,
			"Done":   done,
		}
		//mu.Unlock()
		event := &proto.Event{proto.DATA_COLLECTION_AP, pm}
		if done {
			fmt.Println("done status:", done)
		}

		util.Send(accessPoint.Socket, accessPoint.CloudServiceProviderAddr, util.Encode(event))
		//If each piece of trust data is sent without interval, packet corruption will occur, so the interval is 1 microsecond
		time.Sleep(10.0 * time.Microsecond)
	}

	fmt.Println("[AP] Trust data has been sent.")
	accessPoint.Status = AP_CONNECTED
}

func main() {

	fmt.Println("[AP] AccessPoint started!")

	//get local ip address
	config := util.ReadConfig()
	// check available port
	Port, err := strconv.Atoi(config["ap_port"])
	util.CheckErr(err)
	var LocalAddr *net.UDPAddr = nil
	var Socket *net.UDPConn = nil
	for i := Port; i <= Port+1000; i++ {
		addr, _ := net.ResolveUDPAddr("udp", config["ap_ip"]+":"+strconv.Itoa(i))
		conn, err := net.ListenUDP("udp", addr)
		if err == nil {
			LocalAddr = addr
			Socket = conn
			break
		}
	}
	fmt.Println("[AP] Local address is:", LocalAddr)

	//get csp's ip address
	CSPAddr, err := net.ResolveUDPAddr("udp", config["csp_ip"]+":"+config["csp_port"])
	util.CheckErr(err)
	fmt.Println("[AP] CSP's IP address :", CSPAddr)

	//get OA's ip address
	fmt.Print("[AP] Please enter the IP address of the OperatorAgent: ")
	reader := bufio.NewReader(os.Stdin)
	ipdata, _, err := reader.ReadLine()
	if err == nil {
		fmt.Println("[AP] Enter success!")
	}
	UpperOAStr := string(ipdata)
	OAAddr, err := net.ResolveUDPAddr("udp", UpperOAStr)
	util.CheckErr(err)

	initAP(LocalAddr, Socket, OAAddr, CSPAddr)
	updateTopology()
	go startAPListener()
	registerAP()
	for i := 0; i < ListMaintenceNumber; i++ {
		for accessPoint.Status != AP_COLLECTION {
			//wait for new list
		}
		// add a time to solve interrupt
		localPort := uint(LocalAddr.Port)
		if localPort >= 8002 {
			time.Sleep(4.0 * time.Second)
		} else {	
			time.Sleep(3.0 * time.Second)
		}
		dataCollectionToCSP(localPort)
	}

	fmt.Println("[AP] System exit...")
	//accessPoint.Socket.Close()
}

