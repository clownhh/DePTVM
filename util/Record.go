package util

import (
	"go.dedis.ch/kyber/v4"
)

//store the NE's trust value related data
type Record struct {
	Nym  kyber.Point
	Data []float64
}
