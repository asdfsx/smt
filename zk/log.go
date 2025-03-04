package zk

import (
	"bytes"
	"crypto/elliptic"
	"hash"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	msm2 "github.com/lianghuiqiang9/smt/modfiysm2"
)

func BytesCombine(pBytes ...[]byte) []byte {
	var buffer bytes.Buffer
	for index := 0; index < len(pBytes); index++ {
		buffer.Write(pBytes[index])
	}
	return buffer.Bytes()
}

type Logp struct {
	alphaGx, alphaGy *big.Int
	e, z             *big.Int
}

// prove hash，curve,x
func LogProve(hash hash.Hash, curve elliptic.Curve, Ax, Ay, x *big.Int) *Logp {
	N := curve.Params().N

	alpha, _ := msm2.RandFieldElement(curve, nil)
	alphaGx, alphaGy := curve.ScalarBaseMult(alpha.Bytes())
	hash.Write(BytesCombine(Ax.Bytes(), Ay.Bytes(), alphaGx.Bytes(), alphaGy.Bytes()))
	bytes := hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	e := new(big.Int).SetBytes(bytes)
	e = e.Mod(e, N)
	hash.Reset() //要养成一个良好的习惯。
	z := new(big.Int)
	z.Mul(e, x)
	z.Add(z, alpha)
	z.Mod(z, N)
	return &Logp{alphaGx: alphaGx, alphaGy: alphaGy, e: e, z: z}
}

func (zkp *Logp) LogVerify(hash hash.Hash, curve elliptic.Curve, Ax, Ay *big.Int) bool {
	N := curve.Params().N
	hash.Write(BytesCombine(Ax.Bytes(), Ay.Bytes(), zkp.alphaGx.Bytes(), zkp.alphaGy.Bytes()))
	//计算哈希值
	bytes := hash.Sum(nil)
	hash.Reset()
	e2 := new(big.Int).SetBytes(bytes)
	e2.Mod(e2, N)
	if e2.Cmp(zkp.e) != 0 {
		return false
	}
	zGx, zGy := curve.ScalarBaseMult(zkp.z.Bytes())
	epkx, epky := curve.ScalarMult(Ax, Ay, e2.Bytes())
	z2Gx, z2Gy := curve.Add(zkp.alphaGx, zkp.alphaGy, epkx, epky)

	return zGx.Cmp(z2Gx) == 0 && zGy.Cmp(z2Gy) == 0
}

// prove hash，curve,x
func LogProve1(hash hash.Hash, curve elliptic.Curve, Ax, Ay, Gx, Gy, x *big.Int) *Logp {
	N := curve.Params().N

	alpha, _ := msm2.RandFieldElement(curve, nil)
	alphaGx, alphaGy := curve.ScalarMult(Gx, Gy, alpha.Bytes())
	hash.Write(BytesCombine(Ax.Bytes(), Ay.Bytes(), alphaGx.Bytes(), alphaGy.Bytes()))
	bytes := hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	e := new(big.Int).SetBytes(bytes)
	e = e.Mod(e, N)
	hash.Reset()
	z := new(big.Int)
	z.Mul(e, x)
	z.Add(z, alpha)
	z.Mod(z, N)
	return &Logp{alphaGx: alphaGx, alphaGy: alphaGy, e: e, z: z}
}

func (zkp *Logp) LogVerify1(hash hash.Hash, curve elliptic.Curve, Ax, Ay, Gx, Gy *big.Int) bool {
	N := curve.Params().N
	hash.Write(BytesCombine(Ax.Bytes(), Ay.Bytes(), zkp.alphaGx.Bytes(), zkp.alphaGy.Bytes()))
	//计算哈希值
	bytes := hash.Sum(nil)
	hash.Reset()
	e2 := new(big.Int).SetBytes(bytes)
	e2.Mod(e2, N)
	if e2.Cmp(zkp.e) != 0 {
		return false
	}
	zGx, zGy := curve.ScalarMult(Gx, Gy, zkp.z.Bytes())
	epkx, epky := curve.ScalarMult(Ax, Ay, e2.Bytes())
	z2Gx, z2Gy := curve.Add(zkp.alphaGx, zkp.alphaGy, epkx, epky)

	return zGx.Cmp(z2Gx) == 0 && zGy.Cmp(z2Gy) == 0
}

func (zkp *Logp) MarshalBinary() ([]byte, error) {
	tmp := [4][]byte{zkp.alphaGx.Bytes(), zkp.alphaGy.Bytes(), zkp.e.Bytes(), zkp.z.Bytes()}
	return cbor.Marshal(tmp)
}

func (zkp *Logp) UnmarshalBinary(data []byte) error {
	var tmp [4][]byte
	err := cbor.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}

	zkp.alphaGx = new(big.Int).SetBytes(tmp[0])
	zkp.alphaGy = new(big.Int).SetBytes(tmp[1])
	zkp.e = new(big.Int).SetBytes(tmp[2])
	zkp.z = new(big.Int).SetBytes(tmp[3])
	return nil
}
