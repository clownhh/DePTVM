package util

import (
	"go.dedis.ch/kyber/v4"
)

type Pair struct {
	Nym kyber.Point
	Val float64   //明文是浮点型
}

type EnPair struct {  
	Nym kyber.Point
	Val []byte  //加密后的是字节流
}
