package hhesdk

import "hhe-sdk/symmetric"

type HCipher interface {
	hhesdk.SCipher
	Eval()
}
