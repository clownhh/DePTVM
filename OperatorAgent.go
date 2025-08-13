package main

import (
	"NPTM/blockchain"
	"NPTM/proto"
	"NPTM/shuffle"
	"NPTM/util"
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/proof"
	"go.dedis.ch/kyber/v4/sign/anon"
	"go.dedis.ch/kyber/v4/suites"
	"go.dedis.ch/kyber/v4/util/random"
)

type OperatorAgent struct {
	// client-side config
	LocalAddress *net.UDPAddr
	Socket       *net.UDPConn
	// crypto variables
	Suite      suites.Suite
	PrivateKey kyber.Scalar
	PublicKey  kyber.Point
	G          kyber.Point

	//num of ready OA
	ReadyOANum int
	//Mining status
	MineStatus int
	//Shuffle status
	Status int
	// network topology for OA cluster
	OAList []*net.UDPAddr
	//Stored OA's public key&&addr
	OAKeyList map[string]kyber.Point
	//APs belongs to this OA
	APList []*net.UDPAddr
	//Stored AP's pk(adr->pk)
	APKeyList map[string]kyber.Point
	//CSP address
	CSPAddress *net.UDPAddr
	//Stored CSP's pk(adr->pk)
	CSPKeyList map[string]kyber.Point
	// we only add new clients at the beginning of each round
	// store the new clients's one-time pseudonym
	NewUEsBuffer []kyber.Point

	BlockChain      *blockchain.BlockChain //local blockchain
	winner_block    *blockchain.Block      //store winner_block
	Listm           []util.Pair            //store the <nym (point),val(float)>list
	EnListm         []util.EnPair          //store the <pk (point),val([]byte)>list
	Npk             int64                  //the number of blocks this OA has created
	Records         []util.Record          //store the trust value data
	CandidateBlocks []*blockchain.Block    //stored the lasted blocks from other OAs
	D               int                    //OA's last obfuscation factor         //信任值混淆时的区间间隔
	U               map[string]int         //the latest block's serial number which alters UE(i)'s trust value

	// connected flag
	IsLastOA bool
	// next hop in topology
	NextHop *net.UDPAddr
	// previous hop in topology
	PreviousHop *net.UDPAddr
	// map current public key with previous key(UE)   //将当前公钥映射到以前的密钥（UE）
	KeyMap map[string]kyber.Point

	// used for modPow encryption   （modPow的意思是模幂运算，在椭圆曲线中就是标量乘法）
	Roundkey kyber.Scalar       //在initOA函数中随机选取的
}

//添加
func (o *OperatorAgent) AddAP(addr *net.UDPAddr, key kyber.Point) {
	o.APList = append(o.APList, addr)
	o.APKeyList[addr.String()] = key
}
func (o *OperatorAgent) AddCSP(addr *net.UDPAddr, key kyber.Point) {
	o.CSPKeyList[addr.String()] = key
}
func (o *OperatorAgent) AddOA(addr *net.UDPAddr, key kyber.Point) {
	// delete the OA who has same public key
	for a, k := range o.OAKeyList {
		if k == key {
			delete(o.OAKeyList, a)
			break
		}
	}

	o.OAKeyList[addr.String()] = key
}

//add new NE in buffer

func (o *OperatorAgent) AddUEInBuffer(nym kyber.Point) {
	o.NewUEsBuffer = append(o.NewUEsBuffer, nym)
}

func (o *OperatorAgent) AddIntoDecryptedList(nym kyber.Point, val float64) {
	o.Listm = append(o.Listm, util.Pair{nym, val})
}

func (o *OperatorAgent) AddIntoEecryptedList(key kyber.Point, val []byte) {
	o.EnListm = append(o.EnListm, util.EnPair{key, val})
}

//clear the buffer data
func clearBuffer() {
	// clear buffer
	operatorAgent.NewUEsBuffer = nil
}

//status setting about blockchain   //声明常量
const (
	//status setting about OA's blockchain status
	FREE    = 0
	EVALUE  = 1
	READY   = 2
	MINE    = 3
	RECEIVE = 4
	FINISH  = 5
	//status setting about normal event
	DEFAULT             = 5
	READY_FOR_NEW_ROUND = 6
	READY_FOR_CONSENSUS = 7
	CONSENSUS_END       = 8
	//factors about trust obfuscation
	pth         = 0.5
	k   float64 = 0.17 //the number to adjust the influence of abnormal behavious
	t   float64 = 0.5  //time delay factor
	//factors about consensus && list maintence times
	ConsensusNumber     int = 1
	ListMaintenceNumber int = 3
)

var mu sync.Mutex   
var operatorAgent *OperatorAgent
var srcAddr *net.UDPAddr
var wg sync.WaitGroup

func Handle_OA(buf []byte, addr *net.UDPAddr, tmpOA *OperatorAgent, n int) {
	// decode the whole message
	byteArr := make([]util.ByteArray, 2)
	gob.Register(byteArr)

	srcAddr = addr
	operatorAgent = tmpOA
	event := &proto.Event{}
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	util.CheckErr(err)

	switch event.EventType {
	case proto.AP_REGISTER:
		handleAPRegister(event.Params)
		break
	case proto.OA_REGISTER_REPLY_CSP:
		handleOARegisterCSP(event.Params)
		break
	case proto.OA_REGISTER_OAS:
		handleOARegisterOAs(event.Params, addr)
		break
	case proto.UE_REGISTER_OASIDE:
		handleUERegisterOASide_OA(event.Params)
		break
	case proto.FORWARD_SHUFFLE:
		handleForwardShuffleOA(event.Params)
		break
	case proto.SYNC_REPMAP:
		handleSyncRepList(event.Params)
		break
	case proto.DATA_COLLECTION_OA:
		handleDataColletionOA(event.Params, operatorAgent)
		break
	/*
		case proto.READY_FOR_MINE:
			handleSignalSync(event.Params, operatorAgent, addr)
			break
	*/
	case proto.RECEIVE_BLOCK:
		handleReceiveBlock(event.Params, operatorAgent, addr)
		break
	case proto.UNIQUE_LIST_CONFIRMATION:
		handleListConfirmation(event.Params, operatorAgent, addr)
		break
	case proto.REVERSE_SHUFFLE:
		handleReverseShuffleOA(event.Params)
		break
	default:
		fmt.Println("[OA] Unrecognized request")
		break
	}
}

func handleAPRegister(params map[string]interface{}) {

	publicKey := operatorAgent.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	operatorAgent.AddAP(srcAddr, publicKey)
	fmt.Println("[OA] Receive the registration info from AccessPoint: ", srcAddr)
	pm := map[string]interface{}{
		"reply": true,
	}
	event := &proto.Event{proto.AP_REGISTER_REPLY_OA, pm}
	util.Send(operatorAgent.Socket, srcAddr, util.Encode(event))

}

func handleOARegisterCSP(params map[string]interface{}) {
	publicKey := operatorAgent.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	operatorAgent.AddCSP(srcAddr, publicKey)
	fmt.Println("[OA] Register success to CSP:", srcAddr)
}

func handleOARegisterOAs(params map[string]interface{}, addr *net.UDPAddr) {
	publicKey := operatorAgent.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	operatorAgent.AddOA(addr, publicKey)
	fmt.Println("[OA] Receive the public key from OperatorAgent: ", addr)
}

func handleUERegisterOASide_OA(params map[string]interface{}) {

	publicKey := operatorAgent.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	tepUE, _ := params["UEAddr"].(string)
	tepAP, _ := params["UpperAP"].(string)
	newKey := operatorAgent.Suite.Point().Mul(operatorAgent.Roundkey, publicKey)
	//表示用 operatorAgent.Roundkey 这个标量乘以 publicKey 这个点，并返回结果点（newKey）。
	byteNewKey, _ := newKey.MarshalBinary()
	UEAddr, err := net.ResolveUDPAddr("udp", tepUE)
	//将一个表示 IP 地址和端口的字符串解析为 *net.UDPAddr 类型的地址对象。
	util.CheckErr(err)
	fmt.Println("[OA] Receive  register request from UserEquipment: ", UEAddr)
	operatorAgent.[newKey.String()] = publicKey
	//表示将一个 publicKey 存储在 operatorAgent. 中，键为 newKey 转换为字符串的结果。

	pm := map[string]interface{}{
		"public_key": byteNewKey,
		"UEAddr":     tepUE,
		"UpperAP":    tepAP,
	}

	event := &proto.Event{proto.UE_REGISTER_OASIDE, pm}
	if operatorAgent.NextHop != nil {
		util.Send(operatorAgent.Socket, operatorAgent.NextHop, util.Encode(event))
	} else {
		/* instead of sending new client to server,
		we will send it when finishing this round. Currently we just add it into buffer*/
		APAddr, err := net.ResolveUDPAddr("udp", tepAP)
		util.CheckErr(err)
		operatorAgent.AddUEInBuffer(newKey)
		//send the UE'S upper AP the register info
		fmt.Println("[OA] Send UE's register info to AccessPoint: ", APAddr)
		util.Send(operatorAgent.Socket, APAddr, util.Encode(event))
	}

}

// the part of shuffle
func verifyNeffShuffle(params map[string]interface{}) {

	if _, shuffled := params["shuffled"]; shuffled {
		// get all the necessary parameters
		//将字节数组解码为点列表
		xbarList := util.ProtobufDecodePointList(params["xbar"].([]byte))
		ybarList := util.ProtobufDecodePointList(params["ybar"].([]byte))
		prevKeyList := util.ProtobufDecodePointList(params["prev_keys"].([]byte))
		prevValList := util.ProtobufDecodePointList(params["prev_vals"].([]byte))
		prePublicKey := operatorAgent.Suite.Point()
		prePublicKey.UnmarshalBinary(params["public_key"].([]byte))

		// verify the shuffle
		verifier := shuffle.Verifier(operatorAgent.Suite, nil, prePublicKey, prevKeyList,
			prevValList, xbarList, ybarList)

		err := proof.HashVerify(operatorAgent.Suite, "PairShuffle", verifier, params["proof"].([]byte))
		if err != nil {
			panic("Shuffle verify failed: " + err.Error())
		}
	}

}

//信任值重新绑定
func rebindReputation(newKeys []kyber.Point, newVals [][]byte, finalKeys []kyber.Point) [][]byte {
	size := len(newKeys)
	ret := make([][]byte, size)       //size个[]byte，每一个[]byte还未定义
	m := make(map[string][]byte)      //创建一个新的映射（map），键类型为字符串（string），值类型为字节切片（[]byte）
	for i := 0; i < size; i++ {
		m[newKeys[i].String()] = newVals[i]
	}
	for i := 0; i < size; i++ {
		ret[i] = m[finalKeys[i].String()]
	}
	return ret
}

//该函数将 YbarEn 中的每个点减去 Ytmp 中的对应点，并将结果存储在 Ytmp 中。
func convertToOrigin(YbarEn, Ytmp []kyber.Point) []kyber.Point {
	size := len(YbarEn)
	yyy := make([]kyber.Point, size)

	for i := 0; i < size; i++ {
		yyy[i] = YbarEn[i]
		Ytmp[i].Sub(yyy[i], Ytmp[i])
	}
	return Ytmp
}

// Y is the keys want to shuffle //引入外部包函数为内部函数
func neffShuffle(X []kyber.Point, Y []kyber.Point, rand cipher.Stream) (Xbar, Ybar, Ytmp []kyber.Point, prover proof.Prover) {

	Xbar, Ybar, Ytmp, prover = shuffle.Shuffle(operatorAgent.Suite, nil, operatorAgent.PublicKey, X, Y, rand)

	return       //函数直接返回 Shuffle 函数的结果
}

//处理后向混洗
func handleReverseShuffleOA(params map[string]interface{}) {
	//	params := map[string]interface{}{
	//	"keys":     byteKeys,
	//	"vals":     vals,
	//	"is_start": true,
	//}

	//解码
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	size := len(keyList)
	//创建一个二维字节切片（slice），其中第一维的长度为 size，第二维是动态的 []byte 类型。
	byteValList := make([][]byte, size)
	//if reverse_shffle just start(last OA),no need to verify previous shuffle  //如果reverse_shffle刚刚开始(最后一次OA)，则不需要验证之前的洗牌
	//检查名为 params 的 map 中是否存在键 "is_start"
	//如果存在（ok == true），则执行后续代码 （对值的序列化）
	if _, ok := params["is_start"]; ok {
		//从 params map 中取出键 "vals" 的值
        //使用类型断言 .([]float64) 将其转换为 float64 类型的切片
		intValList := params["vals"].([]float64)
		for i := 0; i < len(intValList); i++ {
			byteValList[i] = util.Float64ToByte(intValList[i])
		}
	} else {
		// verify neff shuffle if needed
		verifyNeffShuffle(params)
		// deserialize data part     //反序列化数据部分
		byteArr := params["vals"].([]util.ByteArray)   //嵌套类型，外面是切片，内部是util.ByteArray结构体
		for i := 0; i < len(byteArr); i++ {
			byteValList[i] = byteArr[i].Arr
		}
	}

	X := make([]kyber.Point, 1)
	X[0] = operatorAgent.PublicKey
	newKeys := make([]kyber.Point, size)
	newVals := make([][]byte, size)
	for i := 0; i < size; i++ {
		// decrypt the public key
		newKeys[i] = operatorAgent.[keyList[i].String()]
		// encrypt the reputation using ElGamal algorithm         //匿名加密  //加密声誉值
		C := anon.Encrypt(operatorAgent.Suite, byteValList[i], anon.Set(X))  //anon.Set(X)设置公钥
		newVals[i] = C
	}

	//序列化
	byteNewKeys := util.ProtobufEncodePointList(newKeys)
	// type is []ByteArr
	byteNewVals := util.SerializeTwoDimensionArray(newVals)

	if size <= 1 {
		// no need to shuffle, just send the package to previous server   //无需洗牌，只需将包发送到上一个服务器即可
		pm := map[string]interface{}{
			"keys": byteNewKeys,
			"vals": byteNewVals,
		}
		event := &proto.Event{proto.REVERSE_SHUFFLE, pm}

		// reset RoundKey and key map   //每轮洗牌/重加密后，清理状态避免关联性泄露与复用风险。
		//将被赋值为生成的随机标量
		operatorAgent.Roundkey = operatorAgent.Suite.Scalar().Pick(random.New())
		operatorAgent.KeyMap = make(map[string]kyber.Point)
		
		if operatorAgent.PreviousHop != nil {
			fmt.Println("[OA] The shuffle of opposite direction is going on.(size <= 1)")
			util.Send(operatorAgent.Socket, operatorAgent.PreviousHop, util.Encode(event))
			//Handle_OA(event, operatorAgent.PreviousHop)
		} else {
			fmt.Println("[OA] The shuffle of opposite direction is done.(size <= 1)")

			operatorAgent.EnListm = nil
			for i := 0; i < len(newKeys); i++ {
				//保存
				operatorAgent.AddIntoEecryptedList(newKeys[i], newVals[i])
			}
			fmt.Println("[OA] The shuffle of forward direction will start.")
			
			return
		}

	}

	Xori := make([]kyber.Point, len(newVals)) //store the ori publickey of sever  //// 存“原始（等价）公钥”的镜像
	for i := 0; i < size; i++ {
		Xori[i] = operatorAgent.Suite.Point().Mul(operatorAgent.PrivateKey, nil) //same as publickey    (OA的公钥)
	}

	byteOri := util.ProtobufEncodePointList(Xori)

	rand := random.New()

	// *** perform neff shuffle here ***   正式洗牌

	//prover：零知识证明
	Xbar, Ybar, Ytmp, prover := neffShuffle(Xori, newKeys, rand)

	//生成可验证的哈希式 ZK 证明，证明“我对两列做了同一置换 + 正确的重加密”，但不泄露置换本身。
	prf, err := proof.HashProve(operatorAgent.Suite, "PairShuffle", prover)
	util.CheckErr(err)

	// this is the shuffled key
	finalKeys := convertToOrigin(Ybar, Ytmp)
	finalVals := rebindReputation(newKeys, newVals, finalKeys)

	//打包要回传给上一跳的数据
	// send data to the next server
	byteXbar := util.ProtobufEncodePointList(Xbar)
	byteYbar := util.ProtobufEncodePointList(Ybar)
	byteFinalKeys := util.ProtobufEncodePointList(finalKeys)
	byteFinalVals := util.SerializeTwoDimensionArray(finalVals)
	bytePublicKey, _ := operatorAgent.PublicKey.MarshalBinary()
	
	// prev keys means the key before shuffle
	pm := map[string]interface{}{
		"xbar":       byteXbar,
		"ybar":       byteYbar,
		"keys":       byteFinalKeys,
		"vals":       byteFinalVals,
		"proof":      prf,
		"prev_keys":  byteOri,              //洗牌前的键
		"prev_vals":  byteNewKeys,
		"shuffled":   true,
		"public_key": bytePublicKey,
	}
	event := &proto.Event{proto.REVERSE_SHUFFLE, pm}
	
	// reset RoundKey and key map  重置状态并回传；
	operatorAgent.Roundkey = operatorAgent.Suite.Scalar().Pick(random.New())
	operatorAgent.KeyMap = make(map[string]kyber.Point)

	//继续进行后向洗牌
	if operatorAgent.PreviousHop != nil {
		fmt.Println("[OA] The shuffle of reverse direction is going on.Pass the list to the previous OperatorAgent.")
		util.Send(operatorAgent.Socket, operatorAgent.PreviousHop, util.Encode(event))
		//Handle_OA(event, operatorAgent.PreviousHop)

	} else {     //后向洗牌完成，
		fmt.Println("[OA] The shuffle of reverse direction is done.")
		//when finishing reverse shuffle,the first OA should store the encrypted listm.
		operatorAgent.EnListm = nil     //加密列表
		for i := 0; i < len(finalKeys); i++ {

			operatorAgent.AddIntoEecryptedList(finalKeys[i], finalVals[i])  //当完成反向洗牌时，第一个OA应该存储加密的列表。
		}

		forwardShuffle()        // 开始进行前向洗牌
		return
	}

}

//进行前向洗牌
func handleForwardShuffleOA(params map[string]interface{}) {

	g := operatorAgent.Suite.Point()
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := params["vals"].([]util.ByteArray)
	size := len(keyList)

	//如果 params 中包含 g，则从 params 中提取并解码 g，并对其进行一些处理。如果没有包含 g，则创建一个新的点 g。
	if val, ok := params["g"]; ok {
		// contains g
		byteG := val.([]byte)
		g = operatorAgent.Suite.Point()
		g.UnmarshalBinary(byteG)
		g = operatorAgent.Suite.Point().Mul(operatorAgent.Roundkey, g)
		// verify the previous shuffle
		verifyNeffShuffle(params)
	} else {
		//gm
		g = operatorAgent.Suite.Point().Mul(operatorAgent.Roundkey, nil)
	}

	//初始化新键和值的切片:
	X1 := make([]kyber.Point, 1)
	X1[0] = operatorAgent.PublicKey
	//store the en/decrypt key&&val
	newKeys := make([]kyber.Point, size)
	newVals := make([][]byte, size)

	for i := 0; i < len(keyList); i++ {
		// encrypt the public key using modPow
		newKeys[i] = operatorAgent.Suite.Point().Mul(operatorAgent.Roundkey, keyList[i])
		// decrypt the reputation using ElGamal algorithm
		MM, err := anon.Decrypt(operatorAgent.Suite, valList[i].Arr, anon.Set(X1), 0, operatorAgent.PrivateKey)
		util.CheckErr(err)
		newVals[i] = MM
		// update key map (nym->publickey)   //假名和公钥的链接
		operatorAgent.KeyMap[newKeys[i].String()] = keyList[i]       //维护一个映射表，把新生成的化名公钥（newKeys[i]）和原来的化名公钥（keyList[i]）对应起来
	}
	//turn the nym//val and gm to byte    //将数据编码为字节数组:
	byteNewKeys := util.ProtobufEncodePointList(newKeys)
	byteNewVals := util.SerializeTwoDimensionArray(newVals)
	byteG, err := g.MarshalBinary()
	util.CheckErr(err)

	if size <= 1 {
		// no need to shuffle, just send the package to next server
		pm := map[string]interface{}{
			"keys": byteNewKeys,
			"vals": byteNewVals,
			"g":    byteG,
		}
		event := &proto.Event{proto.FORWARD_SHUFFLE, pm}
		if operatorAgent.NextHop != nil {
			fmt.Println("[OA] The shuffle of forward direction is going on.Pass the list to the next OperatorAgent(size <= 1)")
			util.Send(operatorAgent.Socket, operatorAgent.NextHop, util.Encode(event))
			//Handle_OA(event, operatorAgent.NextHop)
		} else {
			fmt.Println("[OA] The shuffle of forward direction is done.(size <= 1)")
			//stored the new listm
			operatorAgent.Listm = nil
			for i := 0; i < len(newKeys); i++ {
				operatorAgent.AddIntoDecryptedList(newKeys[i], util.ByteToFloat64(newVals[i]))
			}

			return
		}

		return
	}
	
	//store the OA's privateKey (copy it to the num of vals)
	Xori := make([]kyber.Point, len(newVals))
	for i := 0; i < size; i++ {
		Xori[i] = operatorAgent.Suite.Point().Mul(operatorAgent.PrivateKey, nil)
		//Mul(scalar, point) 是 椭圆曲线上的标量乘法；如果 point == nil，kyber 的约定是使用群的生成元 G（也就是基点）。
		//这行等价于私钥*基点=公钥。
	}
	
	//turn it to byte
	byteOri := util.ProtobufEncodePointList(Xori)
	//has problem,just use the randomstream
	rand := random.New()
	//rand := operatorAgent.Suite.Cipher(abstract.RandomKey)
	
	// *** perform neff shuffle here ***
	Xbar, Ybar, Ytmp, prover := neffShuffle(Xori, newKeys, rand)
	prf, err := proof.HashProve(operatorAgent.Suite, "PairShuffle", prover)
	util.CheckErr(err)

	// this is the shuffled key and val list
	finalKeys := convertToOrigin(Ybar, Ytmp)
	finalVals := rebindReputation(newKeys, newVals, finalKeys)

	// send data to the next server
	byteXbar := util.ProtobufEncodePointList(Xbar)
	byteYbar := util.ProtobufEncodePointList(Ybar)
	byteFinalKeys := util.ProtobufEncodePointList(finalKeys)
	byteFinalVals := util.SerializeTwoDimensionArray(finalVals)
	bytePublicKey, _ := operatorAgent.PublicKey.MarshalBinary()
	
	// prev keys means the key before shuffle
	pm := map[string]interface{}{
		"xbar":       byteXbar,
		"ybar":       byteYbar,
		"keys":       byteFinalKeys,
		"vals":       byteFinalVals,
		"proof":      prf,
		"prev_keys":  byteOri,
		"prev_vals":  byteNewKeys,
		"shuffled":   true,
		"public_key": bytePublicKey,
		"g":          byteG,
	}
	event := &proto.Event{proto.FORWARD_SHUFFLE, pm}

	if operatorAgent.NextHop != nil {
		fmt.Println("[OA] The shuffle of forward direction is going on.Pass the list to the next OperatorAgent.")
		util.Send(operatorAgent.Socket, operatorAgent.NextHop, util.Encode(event))
		//Handle_OA(event, operatorAgent.NextHop)
	} else {
		fmt.Println("[OA] The shuffle of forward direction is done.")
		//when finishing forward shuffle,the first OA should store the new listm.
		operatorAgent.Listm = nil
		operatorAgent.U = make(map[string]int)   //更改UE(i)信任值的最新块序列号
		for i := 0; i < len(finalKeys); i++ {
			operatorAgent.AddIntoDecryptedList(finalKeys[i], util.ByteToFloat64(finalVals[i]))
			operatorAgent.U[finalKeys[i].String()] = 0
		}

		operatorAgent.G = g
		syncListm(byteG)      //   ？
		return
	}

}

//Sync Rep List to APs   //实现了同步新的声誉列表到访问点 (Access Points) 和处理区块链的逻辑。
func handleSyncRepList(params map[string]interface{}) {

	lenth := len(operatorAgent.OAList)
	byteG := params["g"].([]byte)

	//如果当前节点不是最后一个 OA 节点，则将新列表存储在 operatorAgent 中，并初始化 U 映射。
	if operatorAgent.LocalAddress != operatorAgent.OAList[lenth-1] {
		//except last oa,other oas should stored the new list first    //除最后一个oa外，其他oa应首先存储新列表
		nymList := util.ProtobufDecodePointList(params["nyms"].([]byte))
		valList := params["vals"].([]float64)
		operatorAgent.Listm = nil
		operatorAgent.U = make(map[string]int)
		for i := 0; i < len(nymList); i++ {
			operatorAgent.Listm = append(operatorAgent.Listm, util.Pair{nymList[i], valList[i]})
			operatorAgent.U[nymList[i].String()] = 0

		}

		fmt.Println("[OA] Stored the new reputation list success!", operatorAgent.PublicKey)
		time.Sleep(2.0 * time.Second)
	}

	if operatorAgent.BlockChain == nil {
		fmt.Println("[OA] Initial the blockchain.", operatorAgent.PublicKey)
		//if it's the first round ,OA should create blockchain

		createBlockChain(byteG)
		
	} else {
		//else create a new block and add to block chain  //否则创建一个新区块并添加到区块链中
		fmt.Println("[OA] Insert the attached new list to block and add this block to blockchain.")
		operatorAgent.BlockChain.AddBlock(createNewBlock(byteG))
	}

	//send the new list to aps that deployed by it      //将新列表发送给它部署的ap
	event := &proto.Event{proto.SYNC_REPMAP, params}
	for _, APAddr := range operatorAgent.APList {
		fmt.Println("[OA] Send the new reputation list to AccessPoint:", APAddr)
		util.Send(operatorAgent.Socket, APAddr, util.Encode(event))
	}
	//Wait for
	time.Sleep(3 * time.Second)
	operatorAgent.Status = READY_FOR_NEW_ROUND
}

/*
//handle the signal sync event    //处理同步事件
func handleSignalSync(params map[string]interface{}, operatorAgent *OperatorAgent, addr *net.UDPAddr) {
	if ok, _ := params["READY"].(bool); ok == true {
		fmt.Println("[OA] Recieve the sync signal from:", addr)
		operatorAgent.ReadyOANum++
	} else {
		fmt.Println("[OA] Signal verify failed:", addr)
	}

}
*/

///////////////////////////////////////////////////////////////////////////////////////
//function of blockchain
///////////////////////////////////

/////////GenesisBlock and BlockChain

func createBlockChain(gm []byte) {

	bc := &blockchain.BlockChain{}
	genesisblock := genesisBlock(gm)
	bc.AddBlock(genesisblock)

	//initial the OA's blockchain
	operatorAgent.BlockChain = bc
	fmt.Println("[OA] BlockChain system initial success...")

}

//该函数用于将操作代理的 Listm 转换为三个不同的列表：一个字节数组列表、一个浮点数列表和一个合并的字节数组。
func listConversion() ([]byte, []float64, []byte) {
	//初始化
	byteList := [][]byte{}
	nymList := []kyber.Point{}    // kyber.Point 类型的空切片
	valList := []float64{}

	//遍历 Listm 并填充列表
	for _, v := range operatorAgent.Listm {
		nymList = append(nymList, v.Nym)
		valList = append(valList, v.Val)
		byteList = append(byteList, util.Float64ToByte(v.Val))
	}
	byteNym := util.ProtobufEncodePointList(nymList)
	byteList = append(byteList, byteNym)     //字节数组，全部的声誉值在前，全部的假名在后

	return byteNym, valList, bytes.Join(byteList, []byte{})
}

//创建区块链的创世区块，初始化了区块链的一些基础数据
func genesisBlock(gm []byte) *blockchain.Block {
	var K0 int64 = 0 //set the GenesisBlock 's serial number is 1  //序列号设置
	var timestamp int64 = 0   // 时间戳初始化为0
	var prehash []byte = []byte{}    // 前一个区块的哈希值为空，因为这是第一个区块
	var mr0 []byte = []byte{}    // Merkle根0初始化为空

	//mr1 is the merkle root constructed with Lm and gm    // mr1 是用 Lm 和 gm 构造的 Merkle 根
	var D int64 = 0
	nyms, vals, byteList := listConversion()    // 获取当前假名和信任值的转换后的字节数组
	items := [][]byte{(byteList), (gm)}       // 将 byteList 和 gm 放入一个二维字节数组中
	mr1 := blockchain.GetMerkleRoot(items)    // 计算 Merkle 根1

	pk, _ := operatorAgent.PublicKey.MarshalBinary()
	var npk int64 = 0
	var nb int64 = 0
	var nd int64 = 0

	Gblock := blockchain.Block{K0, timestamp, prehash, D, nb, npk, nd, mr0, mr1, pk, nyms, vals}
	return &Gblock
}

func createNewBlock(gm []byte) *blockchain.Block {
	var K0 int64 = 0 //set the first Block 's serial number is 0
	var timestamp int64 = 0
	var prehash []byte = operatorAgent.BlockChain.PreviousBlock().BlockHash()
	var mr0 []byte = []byte{}

	//mr1 is the merkle root constructed with Lm and gm

	nyms, vals, byteList := listConversion()
	items := [][]byte{(byteList), (gm)}
	mr1 := blockchain.GetMerkleRoot(items)
	var D int64 = int64(operatorAgent.D)
	pk, _ := operatorAgent.PublicKey.MarshalBinary()
	var npk int64 = operatorAgent.Npk
	var nb int64 = int64(len(operatorAgent.BlockChain.Blocks))
	var nd int64 = 0

	block := blockchain.Block{K0, timestamp, prehash, D, nb, npk, nd, mr0, mr1, pk, nyms, vals}
	return &block
}

//consensus part
//verify block
func VerifyBlock(signBK []byte, block *blockchain.Block, publicKey kyber.Point) bool {
	//the verify part of work proof

	var intHash big.Int
	var hash []byte
	var intDiff big.Int
	var intTAG big.Int
	var ok bool
	//把困难值和哈希值转化成大整数方便计算
	intTAG.SetString(blockchain.TAG, 16)
	intDiff.SetBytes(blockchain.ComputeDiff(intTAG, block.Npk, block.Nb))
	hash = blockchain.SetHash(block.K0, block.PreHash, block.MerkelRoot0, block.MerkelRoot1, block.PublicKey, block.Timestamp)
	intHash.SetBytes(hash[:])

	//records's and listm's merkle root ,verify the correction of block's update  //记录和计算哈希值
	items0 := [][]byte{(util.ToByteRecords(operatorAgent.Records))}   //信任值数据转化为字节
	_, _, byteList := listConversion()
	items1 := [][]byte{(byteList)}
	MerkelRoot0 := blockchain.GetMerkleRoot(items0)
	MerkelRoot1 := blockchain.GetMerkleRoot(items1)

	//the verify part of sign
	err := util.SchnorrVerify(operatorAgent.Suite, block.BlockHash(), publicKey, signBK)
	if err != nil {
		ok = false
		//fmt.Println("[OA] Signature verification failed!")

	} else {
		//check work proof && records && listm is same
		if intHash.Cmp(&intDiff) == -1 && bytes.Equal(MerkelRoot0, block.MerkelRoot0) && bytes.Equal(MerkelRoot1, block.MerkelRoot1) {
			/*intHash.Cmp(&intDiff) 方法用于比较两个大整数。这个方法返回三个值之一：
			-1 表示 intHash 小于 intDiff；0 表示 intHash 等于 intDiff；1 表示 intHash 大于 intDiff
			这里的条件 intHash.Cmp(&intDiff) == -1 表示 intHash 小于 intDiff。这通常用于验证工作量证明 (Proof of Work)，即计算出的哈希值是否小于目标难度值。
      			后边两个条件的意思是验证计算的Merkel树的根是一致的。
			*/
			ok = true
			//fmt.Println("[OA] Block verify success!")

		} else {
			ok = false
			//fmt.Println("[OA] Block proof of work validation failed!")
		}
	}

	return ok

}

//listening to OA's status,stop receive blocks after theta seconds  //监听OA的状态，在theta秒后停止接收阻塞；实现了一个倒计时监听器，用于在特定时间后停止接收区块
func CountDownListening() {

	//当操作代理的状态是 EVALUE、READY 或 MINE 时，循环等待状态变化
	for operatorAgent.MineStatus == EVALUE || operatorAgent.MineStatus == READY || operatorAgent.MineStatus == MINE {
		//wait util status change to receive
	}
	//状态变为 RECEIVE 时启动倒计时
	if operatorAgent.MineStatus == RECEIVE {
		for i := blockchain.Theta; i >= blockchain.INTERVAL; i = i - blockchain.INTERVAL {
			fmt.Printf("[OA] Stop receive blocks after %d milliseconds...\n", i)
			time.Sleep(blockchain.INTERVAL * time.Millisecond)
			//进入倒计时，间隔时间 blockchain.INTERVAL 毫秒，每次减少这个间隔，直到总时间 blockchain.Theta 用完。
		}
		operatorAgent.MineStatus = FINISH
		fmt.Println("[OA] Stop receive blocks now!")

	} else {
		fmt.Println("[OA] CountDownListening failed!")
		//wg1.Done()
		return
	}

	//after receive time,do not recieve blocks

	//wg1.Done()
	return
}

//实现了共识过程结束后的操作，具体包括将赢家区块添加到区块链、接受赢家区块的列表、重置状态和存储等步骤
func consensusEnd() {

	//添加胜出的区块
	operatorAgent.BlockChain.AddBlock(operatorAgent.winner_block)

	//accept the winner block's listm
	nymList := util.ProtobufDecodePointList(operatorAgent.winner_block.Nyms)    //假名列表需要反序列后再存储
	size := len(nymList)
	operatorAgent.Listm = make([]util.Pair, size)
	for i := 0; i < size; i++ {
		operatorAgent.Listm[i].Nym = nymList[i]
		operatorAgent.Listm[i].Val = operatorAgent.winner_block.Vals[i]
	}

	//when finish a consensus round, OA should reset status and storage     //重置状态和存储 //这里检查当前操作代理的公钥是否与前一个区块的公钥相同，如果相同，则增加 Npk 的值。
	bytePK, _ := operatorAgent.PublicKey.MarshalBinary()
	if reflect.DeepEqual(operatorAgent.BlockChain.PreviousBlock().PublicKey, bytePK) {       //reflect.DeepEqual 深度比较两个值是否相等的函数
		fmt.Println("[OA] The block you created is chosen as the winner block of this round.")
		operatorAgent.Npk++
	}

	//reset
	operatorAgent.winner_block = nil
	operatorAgent.MineStatus = FREE
	operatorAgent.Records = nil
	operatorAgent.Status = CONSENSUS_END


}

//mine

func startMine() {

	//检查挖矿状态
	if operatorAgent.MineStatus == READY {
		fmt.Println("[OA] Start mining...")
		operatorAgent.MineStatus = MINE

		//获取最新区块信息
		previousBlock := operatorAgent.BlockChain.PreviousBlock() //get the latest block
		//设置新块的各种属性
		K0 := previousBlock.K0 + 1
		var D int64 = 0
		var Nb int64 = int64(len(operatorAgent.BlockChain.Blocks))
		var Npk int64 = operatorAgent.Npk
		var Nd int64 = int64(len(operatorAgent.Records))
		var intHash big.Int
		var intDiff big.Int
		var intTAG big.Int
		intTAG.SetString(blockchain.TAG, 16)
		intDiff.SetBytes(blockchain.ComputeDiff(intTAG, Npk, Nb))
		
		//计算HASH
		var hash []byte
		PreHash := previousBlock.BlockHash() //set the prehash
		MerkelRoot0 := []byte{}
		MerkelRoot1 := []byte{}
		Nyms, Vals, byteList := listConversion()
		items0 := [][]byte{(util.ToByteRecords(operatorAgent.Records))}
		items1 := [][]byte{(byteList)}
		//mr0 is root of records
		MerkelRoot0 = blockchain.GetMerkleRoot(items0)
		//mr1 is root of updated listm
		MerkelRoot1 = blockchain.GetMerkleRoot(items1)
		Pk, _ := operatorAgent.PublicKey.MarshalBinary()
		var t int64 = 0 //timestamp

		//find the t
		//计算目标哈希值 (intDiff)，并在一个循环中逐步增加时间戳 t 进行哈希计算，直到找到满足条件的哈希值。如果在这个过程中操作代理的状态变为 RECEIVE，则停止挖矿。
		for t < math.MaxInt64 {
			if operatorAgent.MineStatus == RECEIVE {
				fmt.Println("[OA] Recieve the other block and stop mining!")
				break
			} else {
				hash = blockchain.SetHash(K0, PreHash, MerkelRoot0, MerkelRoot1, Pk, t)
				intHash.SetBytes(hash[:])

				//当找到符合难度要求的哈希值时，构建一个新的区块，将其设置为赢家区块 (winner_block)，并发布该区块。
				if intHash.Cmp(&intDiff) == -1 {
					operatorAgent.MineStatus = RECEIVE
					//insert data to the new block
					new_block := &blockchain.Block{K0, t, PreHash, D, Nb, Npk, Nd, MerkelRoot0, MerkelRoot1, Pk, Nyms, Vals}

					fmt.Println("[OA] Mining success !")
					if operatorAgent.winner_block != nil {
						operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, new_block) //选择赢的区块
					} else {
						operatorAgent.winner_block = new_block
					}
					fmt.Println("[OA] Publish the block !")
					PublishBlock(new_block, operatorAgent, proto.RECEIVE_BLOCK)

					break
				} else {
					t++
				}
			}

		}
	} else {
		fmt.Println("[OA] The initial state of mining is abnormal...")
	}

}

//receive block and verify , then select winner block
//收到新块时处理相应逻辑。该函数根据当前的挖矿状态 (MineStatus)，决定是否接受新的区块并进行验证和处理。
func handleReceiveBlock(Params map[string]interface{}, operatorAgent *OperatorAgent, addr *net.UDPAddr) {

	if operatorAgent.MineStatus == FREE {   //在 FREE 状态下，操作代理不处于区块共识阶段，但如果接收到块，将调用 ReceiveBlock 处理，并通过 BlockWinnnerSelection 方法选择获胜块。
		fmt.Println("[OA] This is not the block consensus stage but recieve a block.")
		ok, block := ReceiveBlock(Params, operatorAgent, addr)
		if ok {
			if operatorAgent.winner_block != nil {
				operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, block)
			} else {
				operatorAgent.winner_block = block
			}
		}

	} else {     //根据不同的挖矿状态 (EVALUE、MINE、READY、RECEIVE、FINISH) 执行相应的逻辑。
		fmt.Println("[OA] Recieve new block from :", addr, "start to verify block and check accept window.")
		ok, block := ReceiveBlock(Params, operatorAgent, addr)
		if ok {
			if operatorAgent.MineStatus == EVALUE {
				fmt.Println("[OA] Receiving other blocks while trust evaluation...")
				operatorAgent.MineStatus = RECEIVE
				if operatorAgent.winner_block != nil {
					operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, block)
				} else {
					operatorAgent.winner_block = block
				}
				fmt.Println("[OA] Receive block success,turning OA's status to RECEIVE...")
			} else if operatorAgent.MineStatus == MINE {
				fmt.Println("[OA] Receiving other blocks while mining...")
				//if ok,set the status to RECEIVE
				operatorAgent.MineStatus = RECEIVE
				if operatorAgent.winner_block != nil {
					operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, block)

				} else {
					operatorAgent.winner_block = block
				}
				fmt.Println("[OA] Receive block success,turning OA's status to RECEIVE...")
			} else if operatorAgent.MineStatus == READY {
				fmt.Println("[OA] A block was received during ready time...")
				operatorAgent.MineStatus = RECEIVE
				if operatorAgent.winner_block != nil {
					operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, block)
				} else {
					operatorAgent.winner_block = block
				}
				fmt.Println("[OA] Receive block success,turning OA's status to RECEIVE...", operatorAgent.PublicKey)

			} else if operatorAgent.MineStatus == RECEIVE {
				fmt.Println("[OA] A block was received during the accept window...", operatorAgent.PublicKey)

				if operatorAgent.winner_block != nil {
					operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, block)
				} else {
					operatorAgent.winner_block = block
				}
				fmt.Println("[OA] Receive block success...")

			} else if operatorAgent.MineStatus == FINISH {

				fmt.Println("[OA] The receive window is closed! Blocks are not received at this time!")
			}
		}
	}
}

//用于接收、解析和验证传入的区块，并返回验证结果和区块本身。该函数根据提供的参数对区块进行解码，并验证其有效性。
func ReceiveBlock(Params map[string]interface{}, operatorAgent *OperatorAgent, addr *net.UDPAddr) (bool, *blockchain.Block) {

	signBK, _ := Params["SignBK"].([]byte)
	block := blockchain.ByteToBlock(Params["Block"].([]byte))

	var ok bool = VerifyBlock(signBK, &block, operatorAgent.OAKeyList[addr.String()])
	return ok, &block
}

//publish block to OAs   //用于在区块生成后，将区块广播给网络中的其他操作代理
func PublishBlock(block *blockchain.Block, operatorAgent *OperatorAgent, eventType int) {
	
	signBK := util.SchnorrSign(operatorAgent.Suite, random.New(), block.BlockHash(), operatorAgent.PrivateKey)  //使用 Schnorr 签名算法对区块的哈希值进行签名
	byteBlock := blockchain.ToByteBlock(*block)    //将区块转换为字节数组
	//bytePublickey, _ := operatorAgent.PublicKey.MarshalBinary()
	pm := map[string]interface{}{
		"Block":  byteBlock,
		"SignBK": signBK,
	}

	event := &proto.Event{eventType, pm}   //创建一个包含区块和签名的事件 event，并指定事件类型 eventType

	//send to OA except itself    //遍历所有的 OA 地址（除了自身），将事件编码并通过网络发送给这些 OA。
	for _, Addr := range operatorAgent.OAList {
		if Addr.String() != operatorAgent.LocalAddress.String() {

			fmt.Println("[OA] Send the block to OA:", Addr)
			util.Send(operatorAgent.Socket, Addr, util.Encode(event))
		}
	}
}

/////////////////////////////////////////////////////////////
/////////function of trust value update

//用于向云服务提供商（CSP，Cloud Service Provider）发送数据收集请求。这个函数将请求封装为一个事件，并通过网络发送给 CSP。
func dataCollectionOA() {

	pm := map[string]interface{}{
		"Require": true,
	}
	event := &proto.Event{proto.DATA_COLLECTION_OA, pm}
	fmt.Println("[OA] Send the data collection require to Cloud Service Provider.")
	util.Send(operatorAgent.Socket, operatorAgent.CSPAddress, util.Encode(event))

}

//用于处理从云服务提供商（CSP）接收的数据收集请求，并验证接收的数据的签名是否有效。如果数据有效，则将其存储到本地记录中。
func handleDataColletionOA(params map[string]interface{}, operatorAgent *OperatorAgent) {
	//检查是否接收到 "Start" 标志
	Nym := operatorAgent.Suite.Point()
	if ok, _ := params["Start"].(bool); ok == true {
		fmt.Println("[OA] Recieve the trust value related data from Cloud Service Provider...", srcAddr)

	}
	//verify the signature and store the record to local records
	// 签名验证成功，将记录存储到本地
	Nym.UnmarshalBinary(params["Nym"].([]byte))
	Data := params["Data"].([]float64)
	record := util.Record{Nym, Data}
	SignRe, _ := params["SignRe"].([]byte)
	err := util.SchnorrVerify(operatorAgent.Suite, util.ToByteRecord(record),
		operatorAgent.CSPKeyList[srcAddr.String()], SignRe)
	//==========================================================test===============================
	//fmt.Println(operatorAgent.CSPKeyList[srcAddr.String()])
	if err == nil {
		// 签名验证成功，将记录存储到本地
		//fmt.Println("[OA] The sign of Cloud Service Provider verify success!")
		//store record to local
		//=================================================test================================
		fmt.Println("=================record output test point==================")
		fmt.Println(record)
		operatorAgent.Records = append(operatorAgent.Records, record)
		fmt.Println(operatorAgent.Records)
	} else {
		//fmt.Println("[OA] The sign of Cloud Service Provider verify failed!")
	}

	//  检查是否接收到 "Done" 标志
	if done, _ := params["Done"].(bool); done == true {
		//print data time
		fmt.Println(record)
		fmt.Println("[OA] Data collection done!")
		operatorAgent.MineStatus = EVALUE
		trustValueUpdate(operatorAgent)

	}

}

func trustValueUpdate(operatorAgent *OperatorAgent) {

	fmt.Println("[OA] Start trust value update...")
	//do the trust value update

	//read normal model  //读取正常模型
	var normal_model []float64 = nil
	opencast1, err1 := os.Open("./datasets/normal_model.csv")
	if err1 != nil {
		fmt.Println("[OA] Normal model open failed!")
	}

	ReadCsv1 := csv.NewReader(opencast1)
	read1, err1 := ReadCsv1.Read()
	util.CheckErr(err1)

	//turn the string to float64
	for j := 0; j < len(read1)-1; j++ {
		tempdata, _ := strconv.ParseFloat(read1[j], 64)
		normal_model = append(normal_model, tempdata)
	}
	opencast1.Close()

	//read abnormal model
	var abnormal_model []float64 = nil
	opencast2, err2 := os.Open("./datasets/abnormal_model.csv")
	if err2 != nil {
		fmt.Println("[OA] Abnormal model open failed!")
	}

	ReadCsv2 := csv.NewReader(opencast2)
	read2, err2 := ReadCsv2.Read()
	util.CheckErr(err2)

	//turn the string to float64
	for j := 0; j < len(read2)-1; j++ {
		tempdata, _ := strconv.ParseFloat(read2[j], 64)
		abnormal_model = append(abnormal_model, tempdata)
	}
	opencast2.Close()
	
	
	//=============================================================================================testtestetstetstestse
	
	fmt.Println(normal_model, abnormal_model)

	////初始化正常/异常行为的计数器
	//the number of normal/abnormal behavious
	var IN map[string]int = make(map[string]int)
	var IA map[string]int = make(map[string]int)
	for index := 0; index < len(operatorAgent.Listm); index++ {
		IN[operatorAgent.Listm[index].Nym.String()] = 0
		IA[operatorAgent.Listm[index].Nym.String()] = 0
	}

	//the number to adjust the influence of abnormal behavious
	//var k float64 = 0.17
	//related number
	var K int = int(operatorAgent.BlockChain.PreviousBlock().K0)

	//time delay
	//var t float64 = 0.5
	
	//================================================================test=================================================
	fmt.Println(len(operatorAgent.Records))
	fmt.Println(operatorAgent)
	//stastic the number of 2 type behavious
	////统计正常和异常行为的数量
	for i := 0; i < len(operatorAgent.Records); i++ {

		//计算异常模型和正常模型与记录数据之间的距离，然后根据距离判断该记录是异常行为还是正常行为。
		if computeDistance(abnormal_model, operatorAgent.Records[i].Data) <= computeDistance(normal_model, operatorAgent.Records[i].Data) {
			IA[operatorAgent.Records[i].Nym.String()]++
		} else {
			IN[operatorAgent.Records[i].Nym.String()]++
		}
		//=================================================================testestest=============================================================================
		fmt.Println(operatorAgent.Records[i].Nym.String(),IA[operatorAgent.Records[i].Nym.String()])
		fmt.Println(operatorAgent.Records[i].Nym.String(),IN[operatorAgent.Records[i].Nym.String()])
	}

	//更新每个组的信任值
	for index, group := range operatorAgent.Listm {

		var newTrustValue float64 = 0.0
		//time_factor 计算时间因子，它基于当前轮次 K 和存储在 operatorAgent.U 中的时间差值。时间因子用于调整信任值，基于行为的时间变化进行指数衰减。
		time_factor := math.Exp(-1.0 * math.Abs(float64(K-operatorAgent.U[group.Nym.String()])) / t)
		//避免除以零的情况：
		if float64(IN[group.Nym.String()]) == 0.0 {
			IN[group.Nym.String()] = 1
		}
		//计算异常行为因子：
		abnormal_factor := k * float64(IA[group.Nym.String()])

		newTrustValue = (1.0/(time_factor+1.0))*
			(float64(IN[group.Nym.String()])-abnormal_factor)/(float64(IN[group.Nym.String()])+abnormal_factor) +
			(time_factor/(time_factor+1.0))*group.Val
		/*第一部分 ((1.0/(time_factor+1.0)) * (float64(IN[group.Nym.String()])-abnormal_factor) / (float64(IN[group.Nym.String()])+abnormal_factor)) 计算行为对信任值的影响，考虑了正常和异常行为的数量。
		第二部分 (time_factor/(time_factor+1.0))*group.Val 计算时间对信任值的影响，平滑地将旧信任值 group.Val 与新计算的部分结合起来。
		*/

		//更新信任值和时间：
		operatorAgent.Listm[index].Val = util.FloatRound(newTrustValue)
		operatorAgent.U[group.Nym.String()] = int(operatorAgent.BlockChain.PreviousBlock().K0 + 1)
	}

	fmt.Println("[OA] Trust value update success!")
	fmt.Println("[OA] Change the status to READY_FOR_CONSENSUS!")
	operatorAgent.Status = READY_FOR_CONSENSUS
	//sendSinalToOAs(operatorAgent)

}

/*
//向其他操作代理（OA）发送准备挖矿的信号
func sendSinalToOAs(operatorAgent *OperatorAgent) {
	// set the parameters to register
	params := map[string]interface{}{
		"READY": true,
	}
	event := &proto.Event{proto.READY_FOR_MINE, params}
	//send the ready siganl to other OA
	for _, OAAddr := range operatorAgent.OAList {

		util.Send(operatorAgent.Socket, OAAddr, util.Encode(event))
		fmt.Println("[OA]Send the signal to OA:", OAAddr)

	}

}
*/
//计算两个浮点数数组之间的欧几里得距离
func computeDistance(a, b []float64) float64 {

	//Distance

	var d float64 = 0.0

	for i := 0; i < len(a); i++ {
		d = d + math.Abs(a[i]-b[i])*math.Abs(a[i]-b[i])
		//对于每个元素，计算 a[i] 和 b[i] 之间的差值的绝对值，并将其平方，然后加到距离变量 d 中。
	}

	d = math.Sqrt(d)

	return d
}

///////////////////////////////////////////////////////////////
/////////list maintenance

//unique list confirmation
//将最新的区块发布给其他OA
func listPublish() {
	//construct candidate blocks    //将最新区块添加到候选区块列表中
	operatorAgent.CandidateBlocks = append(operatorAgent.CandidateBlocks, operatorAgent.BlockChain.PreviousBlock())
	fmt.Println("[OA] Publish the latest block to other OperatorAgents!")
	//将最新区块发布给其他操作代理
	PublishBlock(operatorAgent.BlockChain.PreviousBlock(), operatorAgent, proto.UNIQUE_LIST_CONFIRMATION)
}

//接收所有操作代理（Operator Agent, OA）的最新区块（所投票认同的区块），并选择出一个最终的区块作为共识结果
func listConfirmation() {
	size := len(operatorAgent.OAList)
	for len(operatorAgent.CandidateBlocks) != size {
		//wait for recieve all OA's latest block   //获取 OA 列表的长度，并等待 operatorAgent.CandidateBlocks 列表的长度等于 OA 列表的长度。
	}
	fmt.Println("[OA] Recieve all OA's new block!")

	//初始化计数器：初始化一个 rank 字典来记录每个时间戳的区块出现的次数。
	var rank map[int64]int = make(map[int64]int, size)
	for _, block := range operatorAgent.CandidateBlocks {
		rank[block.Timestamp] = 0
	}

	//统计每个时间戳出现的区块次数：
	for i := 0; i < size; i++ {
		for k, _ := range rank {
			if k == operatorAgent.CandidateBlocks[i].Timestamp {
				rank[k]++
				break
			}
		}
	}

	//find the highest val   //找到最高投票数
	var highest_val int = 0
	for _, v := range rank {

		if v > highest_val {
			highest_val = v
		}
	}

	//选择具有最高投票数的区块：
	var Choosen_Block *blockchain.Block = nil
	var Candidate_Blocks []*blockchain.Block = nil   //一个区块指针的切片，用于存储所有投票数最高的候选区块

	for k, v := range rank {
		if v == highest_val {     //找到最高的v对应的k
			for _, val := range operatorAgent.CandidateBlocks {
				if k == val.Timestamp {      //找到k对应的区块，val是此时遍历的区块
					Candidate_Blocks = append(Candidate_Blocks, val)
					break
				}
			}
		}
	}

	//在多个候选区块中选择最终区块：
	size2 := len(Candidate_Blocks)
	Choosen_Block = Candidate_Blocks[0]   //将 Candidate_Blocks 列表中的第一个区块赋值给 Choosen_Block
	if size2 > 1 {
		for index := 1; index < size2; index++ {
			Choosen_Block = blockchain.BlockWinnnerSelection(Choosen_Block, Candidate_Blocks[index])
		}
	}

	//accept the winner block's listm   //接收赢家区块的 listm
	nymList := util.ProtobufDecodePointList(Choosen_Block.Nyms)
	size3 := len(nymList)
	operatorAgent.Listm = make([]util.Pair, size3)
	for i := 0; i < size3; i++ {
		operatorAgent.Listm[i].Nym = nymList[i]
		operatorAgent.Listm[i].Val = Choosen_Block.Vals[i]
	}

	//重置候选区块列表
	operatorAgent.CandidateBlocks = nil

}

//处理接收到的区块发布确认消息
func handleListConfirmation(Params map[string]interface{}, operatorAgent *OperatorAgent, addr *net.UDPAddr) {

	ok, block := ReceiveBlock(Params, operatorAgent, addr)    //验证和解析接收到的区块
	if ok {
		fmt.Println("[OA] Recieve the pulished block from:", addr)
		operatorAgent.CandidateBlocks = append(operatorAgent.CandidateBlocks, block)
	} else {
		fmt.Println("[OA] The pulished block verify failed!", addr)
	}
}

//trust obfuscation
//在给定数据集上找到合适的 d 值，以便对信任值进行混淆，使其达到特定的匿名性水平
func find_d(d int, DataSet []float64) int {
	//pth := 0.5
	TrustValueSet := make([]float64, len(DataSet))
	copy(TrustValueSet, DataSet)     //将 DataSet 复制到 TrustValueSet 中。
	fmt.Println("**************************************************")
	//fmt.Println("d of this round is:", d)
	var Ntv float64 = 1.0 / float64(d)      //计算每个区间的大小。
	//fmt.Println("Ntv of this round is:", Ntv)

	RN := 1.0 - float64(d)*Ntv     //计算剩余概率
	//record the num and p
	NUM := make([]int, d)
	P := make([]float64, d)

	//do obfuscation  // 对数据集进行混淆  //根据 d 将每个值混淆到相应的区间。
	for index, ele := range TrustValueSet {
		for c := 1; c <= d; c++ {
			if ele > float64(c-1)*Ntv && ele <= float64(c)*Ntv {
				TrustValueSet[index] = float64(c-1) * Ntv

			} else if ele > 1.0-RN && ele <= 1.0 {
				TrustValueSet[index] = 1.0 - RN - Ntv
			}
		}
	}
	//count the number of NUM[i]     // 统计每个区间的数量
	for _, ele := range TrustValueSet {
		for i := 0; i < d; i++ {
			if ele >= float64(i)*Ntv && ele < float64(i+1)*Ntv {
				NUM[i]++
			}
		}
	}

	//calcuelate p[i]     计算每个区间的概率
	for i := 0; i < len(NUM); i++ {
		if NUM[i] != 0 {
			P[i] = 1.0 / float64(NUM[i])
		} else {
			P[i] = 0.0
		}
	}

	//找到最大的概率值
	max := P[0]
	for i := 0; i < len(P); i++ {
		if P[i] > max {
			max = P[i]
		}
	}

	//fmt.Printf("After obfuscation of Ntv [%.6f],the worst anonymous probability is: %.6f\n", Ntv, max)

	if max <= pth {
		//如果最大的概率值小于等于pth，返回当前的d值
		//fmt.Println("Choose the d:", d, "to do obfuscation.")
		return d
	} else {
		return 0
	}

}

//对操作代理 (operatorAgent) 中的信任值列表 (Listm) 进行混淆，以增强隐私保护
func trustObfuscation() {
	//初始化和准备数据集
	size := len(operatorAgent.Listm)
	var DataSet = make([]float64, size)

	//将 Listm 中的信任值拷贝到 DataSet 中
	var d int = 0
	for i := 0; i < size; i++ {
		DataSet[i] = operatorAgent.Listm[i].Val
	}

	//查找合适的 d 值：如果找到了合适的 d 值，立即跳出循环；如果没有找到，d 将保持为 0。
	for j := 30; j >= 10; j-- {
		d := find_d(j, DataSet)
		if d != 0 {
			break
		}
	}

	//使用默认值（30）或找到的 d 值
	if d == 0 {
		fmt.Println("[OA] Use the default value(30) to do obfuscation.")
		d = 30
	} else {
		fmt.Printf("[OA] Use the chossen value(%f) to do obfuscation.\n", d)
	}

	//计算区间大小和剩余概率
	var Ntv float64 = 1.0 / float64(d)
	RN := 1.0 - float64(d)*Ntv
	operatorAgent.D = d
	//进行信任值混淆
	for index := 0; index < size; index++ {
		for c := 1; c <= d; c++ {
			if operatorAgent.Listm[index].Val > float64(c-1)*Ntv && operatorAgent.Listm[index].Val <= float64(c)*Ntv {
				operatorAgent.Listm[index].Val = util.FloatRound(float64(c-1) * Ntv)

			} else if operatorAgent.Listm[index].Val > 1.0-RN && operatorAgent.Listm[index].Val <= 1.0 {
				operatorAgent.Listm[index].Val = util.FloatRound(1.0 - RN - Ntv)
			}
		}
	}
	fmt.Println("[OA] Obfuscation success!", operatorAgent.LocalAddress)
}

//trust evaluation - time delay
//用于对操作代理 (operatorAgent) 中的信任值列表 (Listm) 进行基于时间延迟的信任值评估。
func timeDelayEvaluation() {
	//trust evaluation
	fmt.Println("[OA] Start time delay trust evaluation .", operatorAgent.LocalAddress)
	//related number

	var K int = int(operatorAgent.BlockChain.PreviousBlock().K0)

	//time delay
	//var t float64 = 0.1
	//遍历 Listm 并进行信任值更新
	for index, group := range operatorAgent.Listm {
		var newTrustValue float64 = 0.0
		time_factor := math.Exp(-1.0 * math.Abs(float64(K-operatorAgent.U[group.Nym.String()])) / t)
		newTrustValue = (time_factor / (time_factor + 1.0)) * group.Val
		operatorAgent.Listm[index].Val = util.FloatRound(newTrustValue)
		operatorAgent.U[group.Nym.String()] = 0
	}

	fmt.Println("[OA] Time delay trust evaluation done!", operatorAgent.LocalAddress)
}

/////////////////////////////////
/////////////normal function
//逆向洗牌操作
func reverseShuffle() {

	if len(operatorAgent.Listm) == 0 {
		fmt.Println("[OA] The initial list creation started...")
	}

	// add new clients into reputation map
	//遍历 operatorAgent.NewUEsBuffer 中的新客户，将其添加到解密列表中，并设置初始声誉
	for _, nym := range operatorAgent.NewUEsBuffer {
		operatorAgent.AddIntoDecryptedList(nym, 0.1)
	}
	
	clearBuffer()    //清空缓冲区

	// add previous clients into reputation map
	// construct the parameters    //构建参数列表
	size := len(operatorAgent.Listm)
	keys := make([]kyber.Point, size)
	vals := make([]float64, size)

	for index, _ := range operatorAgent.Listm {
		keys[index] = operatorAgent.Listm[index].Nym
		vals[index] = operatorAgent.Listm[index].Val
	}

	//编码和发送参数：
	byteKeys := util.ProtobufEncodePointList(keys)
	// send signal to OA
	params := map[string]interface{}{
		"keys":     byteKeys,
		"vals":     vals,
		"is_start": true,
	}
	fmt.Println("[OA] The shuffle of reverse direction  started...")
	//fistly, last OA should process this by self
	handleReverseShuffleOA(params)

}

func forwardShuffle() {

	//construct TrustValue list (public & encrypted reputation)
	//构建参数列表
	size := len(operatorAgent.EnListm)
	keys := make([]kyber.Point, size)
	vals := make([][]byte, size)

	//存储
	for index, _ := range operatorAgent.EnListm {
		keys[index] = operatorAgent.EnListm[index].Nym
		vals[index] = operatorAgent.EnListm[index].Val
	}

	//编码
	bytekeys := util.ProtobufEncodePointList(keys)
	bytevals := util.SerializeTwoDimensionArray(vals)
	params := map[string]interface{}{
		"keys": bytekeys,
		"vals": bytevals,
	}
	fmt.Println("[OA] The shuffle of forward direction  started...")
	//event := &proto.Event{proto.FORWARD_SHUFFLE, params}
	//Handle_OA(event, operatorAgent)
	
	//处理
	handleForwardShuffleOA(params)

}

//负责将操作代理 (operatorAgent) 中的 Listm（声誉列表）同步到所有其他操作代理（包括自身）
func syncListm(byteG []byte) {
	// add clients into reputation map
	// construct the parameters
	size := len(operatorAgent.Listm)
	nyms := make([]kyber.Point, size)
	vals := make([]float64, size)

	for index, _ := range operatorAgent.Listm {
		nyms[index] = operatorAgent.Listm[index].Nym
		vals[index] = operatorAgent.Listm[index].Val
	}

	byteNyms := util.ProtobufEncodePointList(nyms)

	// send signal to OA
	params := map[string]interface{}{
		"nyms": byteNyms,
		"vals": vals,
		"g":    byteG,
	}
	fmt.Println("[OA] Sync the new listm to OAs.")
	event := &proto.Event{proto.SYNC_REPMAP, params}

	//the last OA sends new listm to all OAs(including itself)
	//发送同步事件
	for _, OAAddr := range operatorAgent.OAList {
		util.Send(operatorAgent.Socket, OAAddr, util.Encode(event))
	}
}

//负责更新操作代理（operatorAgent）的拓扑结构，包括其前一跳（PreviousHop）、后一跳（NextHop）以及是否为最后一个操作代理（IsLastOA）
func updateTopology() {
	TopologyConfig := util.ReadTopologyConfig()
	list := util.SortMap(TopologyConfig)   //升序排序

	//每个值解析为UDP地址，并将其添加到 operatorAgent.OAList 中，同时处理解析过程中可能发生的错误。
	for _, v := range list {
		addr, err := net.ResolveUDPAddr("udp", v)
		util.CheckErr(err)
		operatorAgent.OAList = append(operatorAgent.OAList, addr)
	}

	//设置 operatorAgent 的前跳和后跳代理，并确定它是否是最后一个代理
	for index, OAAddr := range operatorAgent.OAList {
		//检查当前OA地址是否等于本地地址
		if reflect.DeepEqual(OAAddr.String(), operatorAgent.LocalAddress.String()) {
			// 如果当前OA是列表中的第一个
			if index == 0 {
				operatorAgent.PreviousHop = nil  // 前跳代理为空
				operatorAgent.NextHop = operatorAgent.OAList[1]    // 后跳代理为列表中的第二个
			} else if index == len(operatorAgent.OAList)-1 {        // 如果当前OA是列表中的最后一个
				operatorAgent.PreviousHop = operatorAgent.OAList[index-1]    // 前跳代理为列表中的倒数第二个
				operatorAgent.NextHop = nil    //// 后跳代理为空
				operatorAgent.IsLastOA = true    // 标记为最后一个OA
			} else {         // 如果当前OA既不是第一个也不是最后一个
				operatorAgent.PreviousHop = operatorAgent.OAList[index-1]    // 前跳代理为列表中的前一个
				operatorAgent.NextHop = operatorAgent.OAList[index+1]        // 后跳代理为列表中的后一个
			} 
			break    // 找到本地的OA地址后退出循环
		}

	}

	fmt.Println("[OA] The OA topology list is updated!", operatorAgent.LocalAddress)
	fmt.Println("[OA] OA topology list:", operatorAgent.OAList)
}

//启动 OperatorAgent 的监听器，接收来自其他操作代理的 UDP 消息，并处理这些消息。
func startOAListener() {
	fmt.Println("[OA] OperatorAgent listener started...")
	buf := make([]byte, 4096)
	for {
		n, addr, err := operatorAgent.Socket.ReadFromUDP(buf)
		util.CheckErr(err)
		Handle_OA(buf, addr, operatorAgent, n)
	}
}

//将 OperatorAgent（OA）注册到云服务提供商（CSP）
func registerOAToCSP() {

	// set the parameters to register  设置注册所需的参数
	bytePublicKey, _ := operatorAgent.PublicKey.MarshalBinary()
	params := map[string]interface{}{
		"public_key": bytePublicKey,
	}
	event := &proto.Event{proto.OA_REGISTER_CSP, params}
	//register to CSP
	util.Send(operatorAgent.Socket, operatorAgent.CSPAddress, util.Encode(event))
}


func registerOAToOAs() {

	// set the parameters to register
	bytePublicKey, _ := operatorAgent.PublicKey.MarshalBinary()
	params := map[string]interface{}{
		"public_key": bytePublicKey,
	}
	event := &proto.Event{proto.OA_REGISTER_OAS, params}

	//register to OAs(send the public key)
	for _, OAAddr := range operatorAgent.OAList {
		util.Send(operatorAgent.Socket, OAAddr, util.Encode(event))
	}

}

//初始化 OperatorAgent（OA）的各种参数
func initOA(LocalAddr *net.UDPAddr, Socket *net.UDPConn, CSPAddr *net.UDPAddr) {

	//initlize suite

	suite := edwards25519.NewBlakeSHA256Ed25519()  // Use the edwards25519-curve
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)

	Roundkey := suite.Scalar().Pick(random.New())

	operatorAgent = &OperatorAgent{
		LocalAddr, Socket,
		suite, a, A, nil,
		0, FREE, DEFAULT, nil, make(map[string]kyber.Point), nil, make(map[string]kyber.Point), CSPAddr, make(map[string]kyber.Point), nil,
		nil, nil, nil, nil, 0, nil, nil, 0, nil,
		false, nil, nil, make(map[string]kyber.Point), Roundkey}
	fmt.Println("[OA] Parameter initialization is complete.")
	fmt.Println("[OA] My public key is ", operatorAgent.PublicKey)

}

func printTrustValue(){
	fmt.Println("[OA] Nodes' Trust Value as follow:")
	fmt.Println("[OA] ============================================")
	for seq, trustValue := range operatorAgent.Listm {
		fmt.Println("[OA] ================= Node", seq, "==================\n|---Pseudonyms:", trustValue.Nym, "\n|---TrustValue:", trustValue.Val)
	}
	fmt.Println("[OA] ============================================")
	
	/*输出示例
	[OA] Nodes' Trust Value as follow:
	[OA] ============================================
	[OA] ================= Node 0 ==================
	|---Pseudonyms: Nym1
	|---TrustValue: 0.123456
	[OA] ================= Node 1 ==================
	|---Pseudonyms: Nym2
	|---TrustValue: 0.654321
	[OA] ============================================
	*/
}


//包含初始化操作、配置读取、循环逻辑和命令处理等，确保OperatorAgent 启动并运行整个周期过程
func main() {
	fmt.Println("[OA] OperatorAgent started.")

	//get local ip address      //获取本地IP地址
	config := util.ReadConfig()
	// check available port      //检查可用端口
	Port, err := strconv.Atoi(config["oa_port"])       //用于将字符串转换为整数。Atoi 是 "ASCII to integer" 的缩写。
	util.CheckErr(err)
	var LocalAddr *net.UDPAddr = nil
	var Socket *net.UDPConn = nil
	for i := Port; i <= Port+1000; i++ {
		addr, _ := net.ResolveUDPAddr("udp", config["oa_ip"]+":"+strconv.Itoa(i))  //解析一个UDP地址。具体来说，它将一个IP地址和端口号的字符串转换为一个 *net.UDPAddr 类型的对象
		conn, err := net.ListenUDP("udp", addr)
		if err == nil {    //udp连接未报错
			LocalAddr = addr
			Socket = conn
			break
		}
	}
	fmt.Println("[OA] Local address is:", LocalAddr)
	
	//get csp's ip address    // 获取CSP的IP地址
	CSPAddr, err := net.ResolveUDPAddr("udp", config["csp_ip"]+":"+config["csp_port"])
	util.CheckErr(err)
	fmt.Println("[OA] CSP's IP address :", CSPAddr)

	// 初始化OA
	initOA(LocalAddr, Socket, CSPAddr)
	updateTopology()
	go startOAListener()
	registerOAToCSP()
	
	//wait for AP and UE register     // 等待AP和UE注册
	time.Sleep(10.0 * time.Second)

	// read command and process      // 读取命令并处理
	fmt.Println("[OA] Enter your command.(Type 'ok' to start cycle)")
	reader := bufio.NewReader(os.Stdin)
Loop:
	for {
		//读取并分割命令
		data, _, _ := reader.ReadLine()
		command := string(data)
		commands := strings.Split(command, " ")
		switch commands[0] {
		case "ok":
			registerOAToOAs()   
			break Loop
		default:
			fmt.Println("[OA] Hello!")
		}
	}

	//the cycle of listMaintence
	for k := 0; k < ListMaintenceNumber; k++ {
		if operatorAgent.IsLastOA == true {
			reverseShuffle()   //最后一个OA开启后向混洗
		}
		
		for operatorAgent.Status != READY_FOR_NEW_ROUND {
			//wait for nym update done   // 检测状态，等待假名更新完成
			time.Sleep(1.0 * time.Millisecond)
		}
		//the cycle of consensus
		for i := 0; i < ConsensusNumber; i++ {
			time.Sleep(1.0 * time.Second)
			
			dataCollectionOA()

			for operatorAgent.Status != READY_FOR_CONSENSUS {
				//wait for data collection && evaluation done     //  检测状态，等待数据收集和评估完成
				time.Sleep(1.0 * time.Millisecond)
			}

			//consensus  //共识
			operatorAgent.MineStatus = READY
			
			go CountDownListening()
			
			startMine()
			
			for operatorAgent.MineStatus != FINISH {
				//wait for OA's status turn to FINISH
			}
			
			time.Sleep(1.0 * time.Millisecond)
			
			consensusEnd()
			
		}
		time.Sleep(1.0 * time.Millisecond)
		//list maintenance
		listPublish()
		listConfirmation()
		timeDelayEvaluation()
		printTrustValue()
		trustObfuscation()
		operatorAgent.Status = DEFAULT

	}
	fmt.Println("[OA] Exit system...")

	//operatorAgent.Socket.Close()
}
