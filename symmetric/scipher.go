package hhesdk

// SCipher todo(fedejinich) this should be moved into a more generic 'Cipher' interface
type SCipher interface {
	Encrypt(message []uint64) []uint64
	Decrypt(message []uint64) []uint64
}
