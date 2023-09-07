package modfiysm2

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
)

func TestModfiysm2(t *testing.T) {
	//选定初始化曲线
	C := sm2ec.P256()
	//sk作为私钥
	sk, pkx, pky := Generatekey(C, nil)

	fmt.Println(pky.BitLen())

	hash := sha256.New()
	msg := []byte("HELLO MSM2")

	r, s := Sign(C, hash, msg, sk, nil)

	msg2 := []byte("HELLO MSM2")
	Z := new(big.Int)

	flag := Verify(C, hash, msg2, Z, pkx, pky, r, s)
	fmt.Println("签名验证结果", flag)

	pub := ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     pkx,
		Y:     pky,
	}

	hash.Write(BytesCombine(Z.Bytes(), msg))
	bytes := hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	e2 := new(big.Int).SetBytes(bytes)
	e2 = e2.Mod(e2, C.Params().N)
	hash.Reset() //要养成一个良好的习惯。

	fmt.Println("签名验证结果 using gmsm ", sm2.Verify(&pub, e2.Bytes(), r, s))

}
