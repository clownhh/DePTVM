package util
//utility 实用工具包

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/gob"  //用于进行对象序列化和反序列化。具体来说，它可以将 Go 的数据结构（如结构体、数组、切片、映射等）编码成字节流，方便在网络上传输或者持久化存储；
	"errors"
	"log"
	"math"
	"net"
	"os"
	"reflect"
	"sort"

	"github.com/shopspring/decimal"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"

	"go.dedis.ch/kyber/v4/util/random"
	"go.dedis.ch/protobuf"
)

func SortMap(mp map[string]string) []string {

	//1.将map1的key放到切片中
	var newMap []string = nil
	for k, _ := range mp {
		newMap = append(newMap, k)
	}

	//2.对切片排序  对字符串切片采用字典序升序排列
	sort.Strings(newMap)

	var finalList []string = nil

	for _, s := range newMap {
		for k, v := range mp {
			if s == k {
				finalList = append(finalList, v)
				break
			}
		}
	}

	return finalList
}

将二位字节切片转换为ByteArray切片
func SerializeTwoDimensionArray(arr [][]byte) []ByteArray {
	byteArr := make([]ByteArray, len(arr))
	gob.Register(byteArr) //试图使用 gob.Register 注册 byteArr 类型，以便在 gob 编码和解码过程中识别它   //gob.Register(ByteArray{})
	for i := 0; i < len(arr); i++ {
		byteArr[i].Arr = arr[i]
	}
	return byteArr
}

func Encode(event interface{}) []byte {
	var network bytes.Buffer
	err := gob.NewEncoder(&network).Encode(event)
	CheckErr(err)
	return network.Bytes()
}

func Send(conn *net.UDPConn, addr *net.UDPAddr, content []byte) {
	_, err := conn.WriteToUDP(content, addr)
	if err != nil {
		panic(err.Error())
	}
}

func SendToAccessPoint(conn *net.UDPConn, content []byte) {
	_, err := conn.Write(content)
	if err != nil {
		panic(err.Error())
		//panic 是一种触发运行时错误的机制，用于表示程序无法继续执行的严重错误。
	}
}
//下划线 _ 被称为“空白标识符”（blank identifier）。它用于忽略不需要使用的值或变量。
//使用空白标识符时，表示你明确知道有个值存在，但你不需要这个值，因此可以用 _ 来占位，避免编译器报错未使用变量的错误。

func ToHexInt(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}

func ToByteRecords(records []Record) []byte {
	buf := new(bytes.Buffer)
	gob.NewEncoder(buf).Encode(records)
	return buf.Bytes()
}

func ToByteRecord(record Record) []byte {
	buf := new(bytes.Buffer)
	gob.NewEncoder(buf).Encode(record)
	return buf.Bytes()
}

func ByteToRecord(byteRecord []byte) Record {
	record := &Record{}
	err2 := gob.NewDecoder(bytes.NewReader(byteRecord)).Decode(record)
	CheckErr(err2)
	return *record
}

func CheckErr(err error) {
	if err != nil {
		panic(err.Error())
		os.Exit(1)
	}
}

func ProtobufEncodePointList(plist []kyber.Point) []byte {
	byteNym, err := protobuf.Encode(&PointList{plist})
	if err != nil {
		panic(err.Error())
	}
	return byteNym
}

func ProtobufDecodePointList(bytes []byte) []kyber.Point {
	var aPoint kyber.Point
	var tPoint = reflect.TypeOf(&aPoint).Elem()
	//reflect.Type 类型的 .Elem() 方法返回指针指向的元素类型。如果 reflect.Type 表示一个指针类型，则 Elem() 返回指针指向的变量类型；否则，它会引发 panic。
	
	suite := edwards25519.NewBlakeSHA256Ed25519()

	cons := protobuf.Constructors{
		tPoint: func() interface{} { return suite.Point() },
	}
	/*Constructors 映射（map）是一个用于根据类型动态创建对象的映射。映射的键通常是类型（reflect.Type），值是创建该类型对象的函数（通常是一个返回 interface{} 的函数）。
 	这种映射在需要根据类型信息动态创建对象的场景中非常有用，如反序列化、依赖注入等。
  	protobuf.Constructors 是一个映射，其键是反射类型，值是创建该类型对象的函数。
	tPoint 是 kyber.Point 的反射类型。
	func() interface{} { return suite.Point() } 是一个返回 kyber.Point 对象的函数。
	*/

	var msg PointList
	if err := protobuf.DecodeWithConstructors(bytes, &msg, cons); err != nil {
		log.Fatal(err)
	}
	/*protobuf.DecodeWithConstructors(bytes, &msg, cons) 使用构造器映射解码字节数组 bytes 为 msg。
	*/
	return msg.Points

	/*利用反射和构造器映射来动态地解码点列表。这在需要从序列化的数据中恢复复杂对象（如加密点）时非常有用。
	*/
}

func FloatRound(f float64) float64 {

	res, _ := decimal.NewFromFloat(f).Round(6).Float64()
	return res
}

func Float64ToByte(float float64) []byte {
	bits := math.Float64bits(float)
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, bits)
	return bytes
}

func ByteToFloat64(bytes []byte) float64 {
	bits := binary.LittleEndian.Uint64(bytes)
	return math.Float64frombits(bits)
}

//crypto
type Suite interface {
	kyber.Group
	kyber.Encoding
	kyber.XOFFactory
}

// A basic, verifiable signature
type basicSig struct {
	C kyber.Scalar // challenge
	R kyber.Scalar // response
}

// Returns a secret that depends on on a message and a point
func hashSchnorr(suite Suite, message []byte, p kyber.Point) kyber.Scalar {
	pb, _ := p.MarshalBinary()
	c := suite.XOF(pb)   //随机扩展输出
	c.Write(message)   //message写入c
	return suite.Scalar().Pick(c) //从随机源c中选择一个伪随机标量值
}

// This simplified implementation of Schnorr Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity
func SchnorrSign(suite Suite, random cipher.Stream, message []byte,
	privateKey kyber.Scalar) []byte {

	// Create random secret v and public point commitment T
	v := suite.Scalar().Pick(random)
	T := suite.Point().Mul(v, nil)

	// Create challenge c based on message and T
	c := hashSchnorr(suite, message, T)

	// Compute response r = v - x*c
	r := suite.Scalar()
	r.Mul(privateKey, c).Sub(v, r)

	// Return verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	_ = suite.Write(&buf, &sig)
	return buf.Bytes()
}

func SchnorrVerify(suite Suite, message []byte, publicKey kyber.Point,
	signatureBuffer []byte) error {

	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := suite.Read(buf, &sig); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	// Compute base**(r + x*c) == T
	var P, T kyber.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(r, nil), P.Mul(c, publicKey))

	// Verify that the hash based on the message and T
	// matches the challange c from the signature
	c = hashSchnorr(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}
func ElGamalEncrypt(group kyber.Group, pubkey kyber.Point, message []byte) (
	K, C kyber.Point, remainder []byte) {

	// Embed the message (or as much of it as will fit) into a curve point.
	M := group.Point().Embed(message, random.New())
	max := group.Point().EmbedLen()
	if max > len(message) {
		max = len(message)
	}
	remainder = message[max:]
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := group.Scalar().Pick(random.New()) // ephemeral private key
	K = group.Point().Mul(k, nil)          // ephemeral DH public key
	S := group.Point().Mul(k, pubkey)      // ephemeral DH shared secret
	C = S.Add(S, M)                        // message blinded with secret
	return
}

func ElGamalDecrypt(group kyber.Group, prikey kyber.Scalar, K, C kyber.Point) (
	message []byte, err error) {

	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S := group.Point().Mul(prikey, K) // regenerate shared secret
	M := group.Point().Sub(C, S)      // use to un-blind the message
	message, err = M.Data()           // extract the embedded data
	return
}
