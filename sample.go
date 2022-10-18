package main

import (
	"fmt"

	"github.com/herumi/bls-eth-go-binary/bls"
)

var msg string
var msgbyte []byte
var pubs = make(bls.PublicKeys,5)
var signs = make([]bls.Sign,5)
var aggSignbysec bls.Sign

func Sign() {
	for i := 0; i < 5; i++ {
		var sec bls.SecretKey
		sec.SetByCSPRNG()
		msgbyte = []byte(msg)
		pubs[i] = *sec.GetPublicKey()
		signs[i] = *sec.SignByte(msgbyte)
		fmt.Printf("public key !!!!!!!!!!!!!!!!!!!!!!\n")
		fmt.Printf("%d,%s\n", i, pubs[i].SerializeToHexStr())
		fmt.Printf("signature !!!!!!!!!!!!!!!!!!!!!!\n")
		fmt.Printf("%d,%s\n", i, signs[i].SerializeToHexStr())
		fmt.Printf("verify=%v\n", signs[i].VerifyByte(&pubs[i], msgbyte))
	}

}

func AggregateSign() {
	aggSignbysec.Aggregate(signs)


}

func VerifyAggregateFast() {
	fmt.Printf("%s\n", aggSignbysec.FastAggregateVerify(pubs, msgbyte))

		

}


func main() {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	Sign()
	AggregateSign()
	VerifyAggregateFast()
}
