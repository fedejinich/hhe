package hhesdk

import . "github.com/fedejinich/pasta-go"

func NewSCipherPasta(secretKey []uint64, modulus uint64, params CipherParams) SCipher {
	return NewPasta(secretKey, modulus, params)
}
