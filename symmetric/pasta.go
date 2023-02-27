package hhesdk

import (
	"github.com/fedejinich/pasta-go"
)

func NewSCipherPasta(secretKey []uint64, modulus uint64, params pasta.CipherParams) SCipher {
	return pasta.NewPasta(secretKey, modulus, params)
}
