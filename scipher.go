package hhesdk

import "github.com/fedejinich/pasta-go"

type Pasta = pasta.Pasta

type SCipher interface {
	Encrypt(message []uint64) []uint64
	Decrypt(message []uint64) []uint64
}
