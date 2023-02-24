package hhesdk

import (
	"fmt"

	. "github.com/fedejinich/pasta-go"
)

type SCipher interface {
	Encrypt(message []uint64) []uint64
	Decrypt(message []uint64) []uint64
}

type SCipherType int

const (
	PASTA SCipherType = iota
	AES
)

type PastaParams struct {
	SecretKey    []uint64
	Modulus      uint64
	CipherParams CipherParams
}

type SCipherConfig struct {
	PastaParams *PastaParams
}

func NewSCipher(t SCipherType, config SCipherConfig) SCipher {
	switch t {
	case PASTA:
		if config.PastaParams == nil {
			fmt.Printf("config not found, setup cipher with 'pastaParams'")
			return nil
		}
		config := config.PastaParams
		return NewPasta(config.SecretKey, config.Modulus, config.CipherParams)
	default:
		return nil
	}
}
