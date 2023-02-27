package hhesdk

type Cipher interface {
	Encrypt(message []uint64) []uint64
	Decrypt(message []uint64) []uint64
}
