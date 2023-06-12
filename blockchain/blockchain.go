package blockchain

import (
	"NPTM/util"
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"fmt"
	"math/big"

	"github.com/izqui/helpers"
	"github.com/xsleonard/go-merkle"
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

//set Block's listm to type byte
type Block struct {
	K0        int64
	Timestamp int64
	PreHash   []byte

	//the body data
	D           int64 // the last obfuscation 's factor
	Nb          int64 //the number of blocks have exist
	Npk         int64 //creator's work number
	Nd          int64 // the number of data in this block
	MerkelRoot0 []byte
	MerkelRoot1 []byte
	PublicKey   []byte
	//the list <nym(byte),val(float64)>
	Nyms []byte
	Vals []float64
}

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
	bc.Blocks = append(bc.Blocks, bl)
}

func ComputeDiff(TAG big.Int, Npk int64, Nb int64) []byte {
	if Npk == 0 {
		return TAG.Bytes()
	} else {
		var intNpk = big.NewInt(Npk)
		var intNb = big.NewInt(Nb)
		FinalDiff := TAG.Mul(&TAG, intNb.Div(intNb, intNpk))
		return FinalDiff.Bytes()
	}
}

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

func SetHash(K int64, PreHash []byte, mr0 []byte, mr1 []byte, pk []byte, t int64) []byte {
	information := bytes.Join([][]byte{
		util.ToHexInt(K),
		PreHash,
		mr0,
		mr1,
		pk,
		util.ToHexInt(t),
	},
		[]byte{},
	)
	hash := helpers.SHA256(information)
	return hash
}

//set the block's hash value(self)
func (b *Block) BlockHash() []byte {
	//first
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
		info = append(info, util.Float64ToByte(b.Vals[i]))
	}

	hash := helpers.SHA256(bytes.Join(info, []byte{}))
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

//block winner selection (done)
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
func GetMerkleRoot(items [][]byte) []byte {
	tree := merkle.NewTree()
	err := tree.Generate(items, md5.New())
	if err != nil {
		fmt.Println(err)
	}

	return tree.Root().Hash
}
