package blockchain

import (
	"NPTM/util"
	"bytes" //提供了用于操作字节切片 ([]byte) 的函数。它在处理字符串、数据缓冲区、以及二进制数据时非常有用。bytes 包中的许多函数与 strings 包中的函数类似，但它们处理的是字节切片而不是字符串。
	"crypto/md5"
	"encoding/gob"
	"fmt"
	"math/big"  /*提供了任意精度的整数、浮点数和有理数的基本运算。该包中的数据类型和函数允许对大于 int64 或 float64 类型所能表示的数值进行精确计算。主要的类型和功能包括：
		Int：任意精度的整数。
		Rat：有理数，以两个 Int 表示分子和分母。
		Float：任意精度的浮点数。 */

	"github.com/izqui/helpers"      //提供了一些常用的实用函数。这些函数涵盖了多种功能，主要集中在处理加密哈希、编码、随机数生成等方面
	"github.com/xsleonard/go-merkle"     //用于构建和操作 Merkle 树的 Go 语言库
)

//go run main.go AccessPoint.go CloudServiceProvider.go NetworkNode.go OperatorAgent.go
const (
	TAG      = "000fffffffffffffffffffffffffffffeecfae81b1b9b3c908810b10a1b56001" //A basic difficulty.
	Nbr      = 10                                                                 //The threshold of the number of blocks that a miner has created.
	Ntr      = 50                                                                 //The threshold number of APs whose provided trust-related data in a block
	Theta    = 1500                                                               //recieve window
	INTERVAL = 750                                                                //time interval
)

type BlockChain struct {
	Blocks []*Block //the array of the set of his block's pointer
}

//set Block's listm to type byte   //区块结构
type Block struct {
	K0        int64
	Timestamp int64
	PreHash   []byte

	//the body data
	D           int64 // the last obfuscation 's factor    //最后一个混淆因素   //困难因子
	Nb          int64 //the number of blocks have exist    //已存在的块的数量
	Npk         int64 //creator's work number              //创建者生成了多少区块
	Nd          int64 // the number of data in this block  //该块中的数据数
	MerkelRoot0 []byte
	MerkelRoot1 []byte
	PublicKey   []byte
	//the list <nym(byte),val(float64)>
	Nyms []byte                       //切片同时存储了过程值
	Vals []float64
}

//返回区块链中的最后一个区块
func (bc *BlockChain) PreviousBlock() *Block {
	l := len(bc.Blocks)
	if l == 0 {
		return nil
	} else {
		return bc.Blocks[l-1]
	}
}

//add the block into blockchain
func (bc *BlockChain) AddBlock(bl *Block) {
	bc.Blocks = append(bc.Blocks, bl)   //append切片增加一项
}

//计算挖矿的难度，基于给定的参数 TAG、Npk（该单位创建的区块数量）和 Nb（参考编号）。
func ComputeDiff(TAG big.Int, Npk int64, Nb int64) []byte {
	if Npk == 0 {
		return TAG.Bytes()
	} else {
		var intNpk = big.NewInt(Npk)
		var intNb = big.NewInt(Nb)
		FinalDiff := TAG.Mul(&TAG, intNb.Div(intNb, intNpk))   //计算 Nb 除以 Npk 的结果，并将其与 TAG 相乘
		return FinalDiff.Bytes()
	}
}

//将 Block 结构体转换为字节数组
func ToByteBlock(block Block) []byte {
	buf := new(bytes.Buffer)
	gob.NewEncoder(buf).Encode(block)
	return buf.Bytes()
}

func ByteToBlock(byteBlock []byte) Block {
	var block *Block = &Block{}
	err := gob.NewDecoder(bytes.NewReader(byteBlock)).Decode(block)
	util.CheckErr(err)
	return *block
}

//生成区块链中区块的哈希值
func SetHash(K int64, PreHash []byte, mr0 []byte, mr1 []byte, pk []byte, t int64) []byte {
	/*K：一个 int64 类型的整数，表示某个值。
	PreHash：一个字节数组，表示前一个区块的哈希值。
	mr0：一个字节数组，表示 Merkle 树的根哈希值。
	mr1：另一个字节数组，表示另一个 Merkle 树的根哈希值。
	pk：一个字节数组，表示公钥。
	t：一个 int64 类型的整数，表示时间戳。
	*/
	
	//将多个字节切片连接成一个字节切片
	/*func Join(s [][]byte, sep []byte) []byte
	s：一个字节切片的切片，即 [][]byte。
	sep：用于连接每个字节切片的分隔符。
	这个函数将 s 中的每个字节切片使用 sep 连接起来，返回一个新的字节切片。
	*/
	information := bytes.Join([][]byte{   //第一个参数：二维切片
		util.ToHexInt(K),
		PreHash,
		mr0,
		mr1,
		pk,
		util.ToHexInt(t),
	},
		[]byte{},      //第二个参数是一个空字节切片 []byte{}，表示在连接这些字节切片时不使用任何分隔符。
	)
	hash := helpers.SHA256(information)    //计算 SHA-256 哈希值
	return hash
}

//set the block's hash value(self)
func (b *Block) BlockHash() []byte {
	//first         //将区块的各个字段转换为字节切片并存储在一个二维字节切片 info 中
	info := [][]byte{
		util.ToHexInt(b.K0),
		util.ToHexInt(b.Timestamp),
		b.PreHash,
		util.ToHexInt(b.D),
		util.ToHexInt(b.Nb),
		util.ToHexInt(b.Npk),
		util.ToHexInt(b.Nd),
		b.MerkelRoot0,
		b.MerkelRoot1,
		b.PublicKey,
		b.Nyms,
	}
	for i := 0; i < len(b.Vals); i++ {
		info = append(info, util.Float64ToByte(b.Vals[i]))    //将每个浮点数值转换为字节切片，并添加到 info 数组中
	}

	hash := helpers.SHA256(bytes.Join(info, []byte{}))   //使用 bytes.Join 函数将 info 数组中的所有字节切片连接成一个大的字节切片，然后对该字节切片进行 SHA256 哈希计算
	return hash
}

func (b *Block) PrintBlock() {

	fmt.Println("Start print a block :")
	fmt.Println("The block's creator is", b.PublicKey)
	fmt.Println("The block's serial number is:", b.K0)
	fmt.Println("The block's timestamp is:", b.Timestamp)
	fmt.Println("The block's previous hash is: ", b.PreHash)
	fmt.Println("The block's obfuscation factor is: ", b.D)
	fmt.Printf("When this block is created, there is already %d block in the blockchain.\n", b.Nb)
	fmt.Printf("The block's creator has created %d blocks.", b.Npk)
	fmt.Println("The block's listm is constructed with ", b.Nd, "trust-related data.")

}

//block winner selection (done)    //区块链系统中的区块赢家选择算法
func BlockWinnnerSelection(block0, block1 *Block) *Block {

	if block0.Timestamp != block1.Timestamp {
		if block0.Timestamp < block1.Timestamp {
			return block0
		} else {
			return block1
		}
	} else if block0.Npk != block1.Npk {
		if block0.Npk < block1.Npk {
			return block0
		} else {
			return block1
		}
	} else if block0.Nd != block1.Nd {
		if block0.Nd > block1.Nd {
			return block0
		} else {
			return block1
		}
	} else if bytes.Compare(block0.BlockHash(), block1.BlockHash()) < 0 {
		return block0
	} else {
		return block1
	}

}

//Get the MerkleRoot's hash      
//Merkle 树是一种树形结构，在区块链和其他数据完整性验证应用中非常常见。它通过将数据分片逐级哈希化，最终得到一个唯一的根哈希值，从而可以高效地验证任何一个数据分片是否属于原始数据集。
func GetMerkleRoot(items [][]byte) []byte {
	tree := merkle.NewTree()
	err := tree.Generate(items, md5.New())  //生成了一个 Merkle 树。items 是一个二维字节切片，表示要包含在树中的数据分片。md5.New() 指定了用于生成哈希的哈希函数（在这里使用的是 MD5）。
	if err != nil {
		fmt.Println(err)
	}

	return tree.Root().Hash  //返回了 Merkle 树的根哈希值。
}
