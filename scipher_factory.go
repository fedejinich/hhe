package hhesdk

import (
	"fmt"

	. "github.com/fedejinich/pasta-go"
)

type SCipherType int

const (
	PASTA SCipherType = iota
	AES
)

type PastaParams struct {
	secretKey    []uint64
	modulus      uint64
	cipherParams CipherParams
}

type ScipherFactory struct {
	pastaParams *PastaParams
}

func (f *ScipherFactory) NewSCipher(t SCipherType) SCipher {
	switch t {
	case PASTA:
		if f.pastaParams == nil {
			fmt.Printf("config not found, setup cipher with 'pastaParams'")
			return nil
		}
		config := f.pastaParams
		return NewPasta(config.secretKey, config.modulus, config.cipherParams)
	default:
		return nil
	}
}
