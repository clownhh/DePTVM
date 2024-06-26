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
	D               int                    //OA's last obfuscation factor
	U               map[string]int         //the latest block's serial number which alters UE(i)'s trust value

	// connected flag
	IsLastOA bool
	// next hop in topology
	NextHop *net.UDPAddr
	// previous hop in topology
	PreviousHop *net.UDPAddr
	// map current public key with previous key(UE)
	KeyMap map[string]kyber.Point

	// used for modPow encryption
	Roundkey kyber.Scalar
}

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
	operatorAgent.KeyMap[newKey.String()] = publicKey
	//表示将一个 publicKey 存储在 operatorAgent.KeyMap 中，键为 newKey 转换为字符串的结果。

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

func rebindReputation(newKeys []kyber.Point, newVals [][]byte, finalKeys []kyber.Point) [][]byte {
	size := len(newKeys)
	ret := make([][]byte, size)
	m := make(map[string][]byte)
	for i := 0; i < size; i++ {
		m[newKeys[i].String()] = newVals[i]
	}
	for i := 0; i < size; i++ {
		ret[i] = m[finalKeys[i].String()]
	}
	return ret
}

func convertToOrigin(YbarEn, Ytmp []kyber.Point) []kyber.Point {
	size := len(YbarEn)
	yyy := make([]kyber.Point, size)

	for i := 0; i < size; i++ {
		yyy[i] = YbarEn[i]
		Ytmp[i].Sub(yyy[i], Ytmp[i])
	}
	return Ytmp
}

// Y is the keys want to shuffle
func neffShuffle(X []kyber.Point, Y []kyber.Point, rand cipher.Stream) (Xbar, Ybar, Ytmp []kyber.Point, prover proof.Prover) {

	Xbar, Ybar, Ytmp, prover = shuffle.Shuffle(operatorAgent.Suite, nil, operatorAgent.PublicKey, X, Y, rand)

	return
}

func handleReverseShuffleOA(params map[string]interface{}) {

	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	size := len(keyList)
	byteValList := make([][]byte, size)
	//if reverse_shffle just start(last OA),no need to verify previous shuffle
	if _, ok := params["is_start"]; ok {
		intValList := params["vals"].([]float64)
		for i := 0; i < len(intValList); i++ {
			byteValList[i] = util.Float64ToByte(intValList[i])
		}
	} else {
		// verify neff shuffle if needed
		verifyNeffShuffle(params)
		// deserialize data part
		byteArr := params["vals"].([]util.ByteArray)
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
		newKeys[i] = operatorAgent.KeyMap[keyList[i].String()]
		// encrypt the reputation using ElGamal algorithm
		C := anon.Encrypt(operatorAgent.Suite, byteValList[i], anon.Set(X))
		newVals[i] = C
	}

	byteNewKeys := util.ProtobufEncodePointList(newKeys)
	// type is []ByteArr
	byteNewVals := util.SerializeTwoDimensionArray(newVals)

	if size <= 1 {
		// no need to shuffle, just send the package to previous server
		pm := map[string]interface{}{
			"keys": byteNewKeys,
			"vals": byteNewVals,
		}
		event := &proto.Event{proto.REVERSE_SHUFFLE, pm}

		// reset RoundKey and key map
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

				operatorAgent.AddIntoEecryptedList(newKeys[i], newVals[i])
			}
			fmt.Println("[OA] The shuffle of forward direction will start.")
			return
		}

	}

	Xori := make([]kyber.Point, len(newVals)) //store the ori publickey of sever
	for i := 0; i < size; i++ {
		Xori[i] = operatorAgent.Suite.Point().Mul(operatorAgent.PrivateKey, nil) //same as publickey
	}

	byteOri := util.ProtobufEncodePointList(Xori)

	rand := random.New()

	// *** perform neff shuffle here ***

	Xbar, Ybar, Ytmp, prover := neffShuffle(Xori, newKeys, rand)

	prf, err := proof.HashProve(operatorAgent.Suite, "PairShuffle", prover)
	util.CheckErr(err)

	// this is the shuffled key
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
	}
	event := &proto.Event{proto.REVERSE_SHUFFLE, pm}
	// reset RoundKey and key map
	operatorAgent.Roundkey = operatorAgent.Suite.Scalar().Pick(random.New())
	operatorAgent.KeyMap = make(map[string]kyber.Point)

	if operatorAgent.PreviousHop != nil {
		fmt.Println("[OA] The shuffle of reverse direction is going on.Pass the list to the previous OperatorAgent.")
		util.Send(operatorAgent.Socket, operatorAgent.PreviousHop, util.Encode(event))
		//Handle_OA(event, operatorAgent.PreviousHop)

	} else {
		fmt.Println("[OA] The shuffle of reverse direction is done.")
		//when finishing reverse shuffle,the first OA should store the encrypted listm.
		operatorAgent.EnListm = nil
		for i := 0; i < len(finalKeys); i++ {

			operatorAgent.AddIntoEecryptedList(finalKeys[i], finalVals[i])
		}

		forwardShuffle()
		return
	}

}

func handleForwardShuffleOA(params map[string]interface{}) {

	g := operatorAgent.Suite.Point()
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := params["vals"].([]util.ByteArray)
	size := len(keyList)

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
		// update key map (nym->publickey)
		operatorAgent.KeyMap[newKeys[i].String()] = keyList[i]
	}
	//turn the nym//val and gm to byte
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
		operatorAgent.U = make(map[string]int)
		for i := 0; i < len(finalKeys); i++ {
			operatorAgent.AddIntoDecryptedList(finalKeys[i], util.ByteToFloat64(finalVals[i]))
			operatorAgent.U[finalKeys[i].String()] = 0
		}

		operatorAgent.G = g
		syncListm(byteG)
		return
	}

}

//Sync Rep List to APs
func handleSyncRepList(params map[string]interface{}) {

	lenth := len(operatorAgent.OAList)
	byteG := params["g"].([]byte)

	if operatorAgent.LocalAddress != operatorAgent.OAList[lenth-1] {
		//except last oa,other oas should stored the new list first
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
		//else create a new block and add to block chain
		fmt.Println("[OA] Insert the attached new list to block and add this block to blockchain.")
		operatorAgent.BlockChain.AddBlock(createNewBlock(byteG))
	}

	//send the new list to aps that deployed by it
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
//handle the signal sync event
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

func listConversion() ([]byte, []float64, []byte) {
	byteList := [][]byte{}
	nymList := []kyber.Point{}

	valList := []float64{}
	for _, v := range operatorAgent.Listm {
		nymList = append(nymList, v.Nym)
		valList = append(valList, v.Val)
		byteList = append(byteList, util.Float64ToByte(v.Val))
	}
	byteNym := util.ProtobufEncodePointList(nymList)
	byteList = append(byteList, byteNym)

	return byteNym, valList, bytes.Join(byteList, []byte{})
}

func genesisBlock(gm []byte) *blockchain.Block {
	var K0 int64 = 0 //set the GenesisBlock 's serial number is 1
	var timestamp int64 = 0
	var prehash []byte = []byte{}
	var mr0 []byte = []byte{}

	//mr1 is the merkle root constructed with Lm and gm
	var D int64 = 0
	nyms, vals, byteList := listConversion()
	items := [][]byte{(byteList), (gm)}
	mr1 := blockchain.GetMerkleRoot(items)

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
	intTAG.SetString(blockchain.TAG, 16)
	intDiff.SetBytes(blockchain.ComputeDiff(intTAG, block.Npk, block.Nb))
	hash = blockchain.SetHash(block.K0, block.PreHash, block.MerkelRoot0, block.MerkelRoot1, block.PublicKey, block.Timestamp)
	intHash.SetBytes(hash[:])

	//records's and listm's merkle root ,verify the correction of block's update
	items0 := [][]byte{(util.ToByteRecords(operatorAgent.Records))}
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
			ok = true
			//fmt.Println("[OA] Block verify success!")

		} else {
			ok = false
			//fmt.Println("[OA] Block proof of work validation failed!")
		}
	}

	return ok

}

//listening to OA's status,stop receive blocks after theta seconds
func CountDownListening() {

	for operatorAgent.MineStatus == EVALUE || operatorAgent.MineStatus == READY || operatorAgent.MineStatus == MINE {
		//wait util status change to receive
	}
	if operatorAgent.MineStatus == RECEIVE {
		for i := blockchain.Theta; i >= blockchain.INTERVAL; i = i - blockchain.INTERVAL {
			fmt.Printf("[OA] Stop receive blocks after %d milliseconds...\n", i)
			time.Sleep(blockchain.INTERVAL * time.Millisecond)
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

func consensusEnd() {

	operatorAgent.BlockChain.AddBlock(operatorAgent.winner_block)

	//accept the winner block's listm
	nymList := util.ProtobufDecodePointList(operatorAgent.winner_block.Nyms)
	size := len(nymList)
	operatorAgent.Listm = make([]util.Pair, size)
	for i := 0; i < size; i++ {
		operatorAgent.Listm[i].Nym = nymList[i]
		operatorAgent.Listm[i].Val = operatorAgent.winner_block.Vals[i]
	}

	//when finish a consensus round, OA should reset status and storage
	bytePK, _ := operatorAgent.PublicKey.MarshalBinary()
	if reflect.DeepEqual(operatorAgent.BlockChain.PreviousBlock().PublicKey, bytePK) {
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

	if operatorAgent.MineStatus == READY {
		fmt.Println("[OA] Start mining...")
		operatorAgent.MineStatus = MINE

		previousBlock := operatorAgent.BlockChain.PreviousBlock() //get the latest block
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
		for t < math.MaxInt64 {
			if operatorAgent.MineStatus == RECEIVE {
				fmt.Println("[OA] Recieve the other block and stop mining!")
				break
			} else {
				hash = blockchain.SetHash(K0, PreHash, MerkelRoot0, MerkelRoot1, Pk, t)
				intHash.SetBytes(hash[:])
				if intHash.Cmp(&intDiff) == -1 {
					operatorAgent.MineStatus = RECEIVE
					//insert data to the new block
					new_block := &blockchain.Block{K0, t, PreHash, D, Nb, Npk, Nd, MerkelRoot0, MerkelRoot1, Pk, Nyms, Vals}

					fmt.Println("[OA] Mining success !")
					if operatorAgent.winner_block != nil {
						operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, new_block)
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

func handleReceiveBlock(Params map[string]interface{}, operatorAgent *OperatorAgent, addr *net.UDPAddr) {

	if operatorAgent.MineStatus == FREE {
		fmt.Println("[OA] This is not the block consensus stage but recieve a block.")
		ok, block := ReceiveBlock(Params, operatorAgent, addr)
		if ok {
			if operatorAgent.winner_block != nil {
				operatorAgent.winner_block = blockchain.BlockWinnnerSelection(operatorAgent.winner_block, block)
			} else {
				operatorAgent.winner_block = block
			}
		}

	} else {
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

func ReceiveBlock(Params map[string]interface{}, operatorAgent *OperatorAgent, addr *net.UDPAddr) (bool, *blockchain.Block) {

	signBK, _ := Params["SignBK"].([]byte)
	block := blockchain.ByteToBlock(Params["Block"].([]byte))

	var ok bool = VerifyBlock(signBK, &block, operatorAgent.OAKeyList[addr.String()])
	return ok, &block
}

//publish block to OAs
func PublishBlock(block *blockchain.Block, operatorAgent *OperatorAgent, eventType int) {

	signBK := util.SchnorrSign(operatorAgent.Suite, random.New(), block.BlockHash(), operatorAgent.PrivateKey)
	byteBlock := blockchain.ToByteBlock(*block)
	//bytePublickey, _ := operatorAgent.PublicKey.MarshalBinary()
	pm := map[string]interface{}{
		"Block":  byteBlock,
		"SignBK": signBK,
	}

	event := &proto.Event{eventType, pm}

	//send to OA except itself
	for _, Addr := range operatorAgent.OAList {
		if Addr.String() != operatorAgent.LocalAddress.String() {

			fmt.Println("[OA] Send the block to OA:", Addr)
			util.Send(operatorAgent.Socket, Addr, util.Encode(event))
		}
	}
}

/////////////////////////////////////////////////////////////
/////////function of trust value update

func dataCollectionOA() {

	pm := map[string]interface{}{
		"Require": true,
	}
	event := &proto.Event{proto.DATA_COLLECTION_OA, pm}
	fmt.Println("[OA] Send the data collection require to Cloud Service Provider.")
	util.Send(operatorAgent.Socket, operatorAgent.CSPAddress, util.Encode(event))

}

func handleDataColletionOA(params map[string]interface{}, operatorAgent *OperatorAgent) {
	Nym := operatorAgent.Suite.Point()
	if ok, _ := params["Start"].(bool); ok == true {
		fmt.Println("[OA] Recieve the trust value related data from Cloud Service Provider...", srcAddr)

	}
	//verify the signature and store the record to local records

	Nym.UnmarshalBinary(params["Nym"].([]byte))
	Data := params["Data"].([]float64)
	record := util.Record{Nym, Data}
	SignRe, _ := params["SignRe"].([]byte)
	err := util.SchnorrVerify(operatorAgent.Suite, util.ToByteRecord(record),
		operatorAgent.CSPKeyList[srcAddr.String()], SignRe)
	//==========================================================test===============================
	//fmt.Println(operatorAgent.CSPKeyList[srcAddr.String()])
	if err == nil {
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

	//read normal model
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
	for i := 0; i < len(operatorAgent.Records); i++ {

		if computeDistance(abnormal_model, operatorAgent.Records[i].Data) <= computeDistance(normal_model, operatorAgent.Records[i].Data) {
			IA[operatorAgent.Records[i].Nym.String()]++
		} else {
			IN[operatorAgent.Records[i].Nym.String()]++
		}
		//=================================================================testestest=============================================================================
		fmt.Println(operatorAgent.Records[i].Nym.String(),IA[operatorAgent.Records[i].Nym.String()])
		fmt.Println(operatorAgent.Records[i].Nym.String(),IN[operatorAgent.Records[i].Nym.String()])
	}

	for index, group := range operatorAgent.Listm {

		var newTrustValue float64 = 0.0
		time_factor := math.Exp(-1.0 * math.Abs(float64(K-operatorAgent.U[group.Nym.String()])) / t)
		if float64(IN[group.Nym.String()]) == 0.0 {
			IN[group.Nym.String()] = 1
		}
		abnormal_factor := k * float64(IA[group.Nym.String()])

		newTrustValue = (1.0/(time_factor+1.0))*
			(float64(IN[group.Nym.String()])-abnormal_factor)/(float64(IN[group.Nym.String()])+abnormal_factor) +
			(time_factor/(time_factor+1.0))*group.Val

		operatorAgent.Listm[index].Val = util.FloatRound(newTrustValue)
		operatorAgent.U[group.Nym.String()] = int(operatorAgent.BlockChain.PreviousBlock().K0 + 1)
	}

	fmt.Println("[OA] Trust value update success!")
	fmt.Println("[OA] Change the status to READY_FOR_CONSENSUS!")
	operatorAgent.Status = READY_FOR_CONSENSUS
	//sendSinalToOAs(operatorAgent)

}

/*
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
func computeDistance(a, b []float64) float64 {

	//Distance

	var d float64 = 0.0

	for i := 0; i < len(a); i++ {
		d = d + math.Abs(a[i]-b[i])*math.Abs(a[i]-b[i])
	}

	d = math.Sqrt(d)

	return d
}

///////////////////////////////////////////////////////////////
/////////list maintenance

//unique list confirmation

func listPublish() {
	//construct candidate blocks
	operatorAgent.CandidateBlocks = append(operatorAgent.CandidateBlocks, operatorAgent.BlockChain.PreviousBlock())
	fmt.Println("[OA] Publish the latest block to other OperatorAgents!")
	PublishBlock(operatorAgent.BlockChain.PreviousBlock(), operatorAgent, proto.UNIQUE_LIST_CONFIRMATION)
}

func listConfirmation() {
	size := len(operatorAgent.OAList)
	for len(operatorAgent.CandidateBlocks) != size {
		//wait for recieve all OA's latest block
	}
	fmt.Println("[OA] Recieve all OA's new block!")

	var rank map[int64]int = make(map[int64]int, size)
	for _, block := range operatorAgent.CandidateBlocks {
		rank[block.Timestamp] = 0
	}

	for i := 0; i < size; i++ {
		for k, _ := range rank {
			if k == operatorAgent.CandidateBlocks[i].Timestamp {
				rank[k]++
				break
			}
		}
	}

	//find the highest val
	var highest_val int = 0
	for _, v := range rank {

		if v > highest_val {
			highest_val = v
		}
	}

	var Choosen_Block *blockchain.Block = nil
	var Candidate_Blocks []*blockchain.Block = nil

	for k, v := range rank {
		if v == highest_val {
			for _, val := range operatorAgent.CandidateBlocks {
				if k == val.Timestamp {
					Candidate_Blocks = append(Candidate_Blocks, val)
					break
				}
			}
		}
	}

	size2 := len(Candidate_Blocks)
	Choosen_Block = Candidate_Blocks[0]
	if size2 > 1 {
		for index := 1; index < size2; index++ {
			Choosen_Block = blockchain.BlockWinnnerSelection(Choosen_Block, Candidate_Blocks[index])
		}
	}

	//accept the winner block's listm
	nymList := util.ProtobufDecodePointList(Choosen_Block.Nyms)
	size3 := len(nymList)
	operatorAgent.Listm = make([]util.Pair, size3)
	for i := 0; i < size3; i++ {
		operatorAgent.Listm[i].Nym = nymList[i]
		operatorAgent.Listm[i].Val = Choosen_Block.Vals[i]
	}

	operatorAgent.CandidateBlocks = nil

}

func handleListConfirmation(Params map[string]interface{}, operatorAgent *OperatorAgent, addr *net.UDPAddr) {

	ok, block := ReceiveBlock(Params, operatorAgent, addr)
	if ok {
		fmt.Println("[OA] Recieve the pulished block from:", addr)
		operatorAgent.CandidateBlocks = append(operatorAgent.CandidateBlocks, block)
	} else {
		fmt.Println("[OA] The pulished block verify failed!", addr)
	}
}

//trust obfuscation
func find_d(d int, DataSet []float64) int {
	//pth := 0.5
	TrustValueSet := make([]float64, len(DataSet))
	copy(TrustValueSet, DataSet)
	fmt.Println("**************************************************")
	//fmt.Println("d of this round is:", d)
	var Ntv float64 = 1.0 / float64(d)
	//fmt.Println("Ntv of this round is:", Ntv)

	RN := 1.0 - float64(d)*Ntv
	//record the num and p
	NUM := make([]int, d)
	P := make([]float64, d)

	//do obfuscation
	for index, ele := range TrustValueSet {
		for c := 1; c <= d; c++ {
			if ele > float64(c-1)*Ntv && ele <= float64(c)*Ntv {
				TrustValueSet[index] = float64(c-1) * Ntv

			} else if ele > 1.0-RN && ele <= 1.0 {
				TrustValueSet[index] = 1.0 - RN - Ntv
			}
		}
	}
	//count the number of NUM[i]
	for _, ele := range TrustValueSet {
		for i := 0; i < d; i++ {
			if ele >= float64(i)*Ntv && ele < float64(i+1)*Ntv {
				NUM[i]++
			}
		}
	}

	//calcuelate p[i]
	for i := 0; i < len(NUM); i++ {
		if NUM[i] != 0 {
			P[i] = 1.0 / float64(NUM[i])
		} else {
			P[i] = 0.0
		}
	}

	max := P[0]

	for i := 0; i < len(P); i++ {
		if P[i] > max {
			max = P[i]
		}
	}

	//fmt.Printf("After obfuscation of Ntv [%.6f],the worst anonymous probability is: %.6f\n", Ntv, max)

	if max <= pth {
		//fmt.Println("Choose the d:", d, "to do obfuscation.")
		return d
	} else {
		return 0
	}

}

func trustObfuscation() {
	size := len(operatorAgent.Listm)
	var DataSet = make([]float64, size)

	var d int = 0
	for i := 0; i < size; i++ {
		DataSet[i] = operatorAgent.Listm[i].Val
	}

	for j := 30; j >= 10; j-- {
		d := find_d(j, DataSet)
		if d != 0 {
			break
		}
	}

	if d == 0 {
		fmt.Println("[OA] Use the default value(30) to do obfuscation.")
		d = 30
	} else {
		fmt.Printf("[OA] Use the chossen value(%f) to do obfuscation.\n", d)
	}

	var Ntv float64 = 1.0 / float64(d)
	RN := 1.0 - float64(d)*Ntv
	operatorAgent.D = d
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
func timeDelayEvaluation() {
	//trust evaluation
	fmt.Println("[OA] Start time delay trust evaluation .", operatorAgent.LocalAddress)
	//related number

	var K int = int(operatorAgent.BlockChain.PreviousBlock().K0)

	//time delay
	//var t float64 = 0.1
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
func reverseShuffle() {

	if len(operatorAgent.Listm) == 0 {
		fmt.Println("[OA] The initial list creation started...")
	}

	// add new clients into reputation map

	for _, nym := range operatorAgent.NewUEsBuffer {
		operatorAgent.AddIntoDecryptedList(nym, 0.1)
	}

	clearBuffer()

	// add previous clients into reputation map
	// construct the parameters
	size := len(operatorAgent.Listm)
	keys := make([]kyber.Point, size)
	vals := make([]float64, size)

	for index, _ := range operatorAgent.Listm {
		keys[index] = operatorAgent.Listm[index].Nym
		vals[index] = operatorAgent.Listm[index].Val
	}

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
	size := len(operatorAgent.EnListm)
	keys := make([]kyber.Point, size)
	vals := make([][]byte, size)

	for index, _ := range operatorAgent.EnListm {
		keys[index] = operatorAgent.EnListm[index].Nym
		vals[index] = operatorAgent.EnListm[index].Val
	}

	bytekeys := util.ProtobufEncodePointList(keys)
	bytevals := util.SerializeTwoDimensionArray(vals)
	params := map[string]interface{}{
		"keys": bytekeys,
		"vals": bytevals,
	}
	fmt.Println("[OA] The shuffle of forward direction  started...")
	//event := &proto.Event{proto.FORWARD_SHUFFLE, params}
	//Handle_OA(event, operatorAgent)
	handleForwardShuffleOA(params)

}

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

	for _, OAAddr := range operatorAgent.OAList {
		util.Send(operatorAgent.Socket, OAAddr, util.Encode(event))
	}
}

func updateTopology() {
	TopologyConfig := util.ReadTopologyConfig()
	list := util.SortMap(TopologyConfig)

	for _, v := range list {
		addr, err := net.ResolveUDPAddr("udp", v)
		util.CheckErr(err)
		operatorAgent.OAList = append(operatorAgent.OAList, addr)
	}

	for index, OAAddr := range operatorAgent.OAList {
		if reflect.DeepEqual(OAAddr.String(), operatorAgent.LocalAddress.String()) {
			if index == 0 {
				operatorAgent.PreviousHop = nil
				operatorAgent.NextHop = operatorAgent.OAList[1]
			} else if index == len(operatorAgent.OAList)-1 {
				operatorAgent.PreviousHop = operatorAgent.OAList[index-1]
				operatorAgent.NextHop = nil
				operatorAgent.IsLastOA = true
			} else {
				operatorAgent.PreviousHop = operatorAgent.OAList[index-1]
				operatorAgent.NextHop = operatorAgent.OAList[index+1]
			}
			break
		}

	}

	fmt.Println("[OA] The OA topology list is updated!", operatorAgent.LocalAddress)
	fmt.Println("[OA] OA topology list:", operatorAgent.OAList)
}

func startOAListener() {
	fmt.Println("[OA] OperatorAgent listener started...")
	buf := make([]byte, 4096)
	for {
		n, addr, err := operatorAgent.Socket.ReadFromUDP(buf)
		util.CheckErr(err)
		Handle_OA(buf, addr, operatorAgent, n)
	}
}

func registerOAToCSP() {

	// set the parameters to register
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
}


func main() {
	fmt.Println("[OA] OperatorAgent started.")

	//get local ip address
	config := util.ReadConfig()
	// check available port
	Port, err := strconv.Atoi(config["oa_port"])
	util.CheckErr(err)
	var LocalAddr *net.UDPAddr = nil
	var Socket *net.UDPConn = nil
	for i := Port; i <= Port+1000; i++ {
		addr, _ := net.ResolveUDPAddr("udp", config["oa_ip"]+":"+strconv.Itoa(i))
		conn, err := net.ListenUDP("udp", addr)
		if err == nil {
			LocalAddr = addr
			Socket = conn
			break
		}
	}
	fmt.Println("[OA] Local address is:", LocalAddr)
	//get csp's ip address
	CSPAddr, err := net.ResolveUDPAddr("udp", config["csp_ip"]+":"+config["csp_port"])
	util.CheckErr(err)
	fmt.Println("[OA] CSP's IP address :", CSPAddr)
	initOA(LocalAddr, Socket, CSPAddr)
	updateTopology()
	go startOAListener()
	registerOAToCSP()
	//wait for AP and UE register
	time.Sleep(10.0 * time.Second)

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
			registerOAToOAs()
			break Loop
		default:
			fmt.Println("[OA] Hello!")
		}
	}

	//the cycle of listMaintence
	for k := 0; k < ListMaintenceNumber; k++ {
		if operatorAgent.IsLastOA == true {
			reverseShuffle()
		}
		for operatorAgent.Status != READY_FOR_NEW_ROUND {
			//wait for nym update done
			time.Sleep(1.0 * time.Millisecond)
		}
		//the cycle of consensus
		for i := 0; i < ConsensusNumber; i++ {
			time.Sleep(1.0 * time.Second)
			dataCollectionOA()

			for operatorAgent.Status != READY_FOR_CONSENSUS {
				//wait for data collection && evaluation done
				time.Sleep(1.0 * time.Millisecond)
			}

			//consensus
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
