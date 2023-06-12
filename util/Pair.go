package util

import (
	"go.dedis.ch/kyber/v4"
)

type Pair struct {
	Nym kyber.Point
	Val float64
}

type EnPair struct {
	Nym kyber.Point
	Val []byte
}
