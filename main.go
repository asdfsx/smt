package main

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/emmansun/gmsm/sm3"
	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/smt"
)

func main() {

	start1 := time.Now()

	//选定初始化曲线
	C := sm2ec.P256()
	//确定参与方人数N<26
	N := 2
	//确定阈值T<=N
	T := 2
	// hash function
	// HashFunc := sha256.New
	HashFunc := sm3.New
	//建立network
	// var net = network.NewNetwork(nil, N, T, C)
	var net = network.NewNetwork2(nil, N, T, C, HashFunc())
	//初始化通信信道
	net.Init()
	//初始化秘密信息map，每个参与方只使用自己的的。
	SecretInfo := make(network.MSecretPartiesInfoMap)

	//paillierkeygen为每一方生成合适的paillier公私钥，persedern数，和Rtig
	fmt.Println("paillierkeygen")
	smt.Paillierkeygen(&net, SecretInfo)
	cost1 := time.Since(start1)
	fmt.Println("paillierkeygen cost=", cost1.Seconds())

	fmt.Println("k", C.Params().N.BitLen(), "mu", net.Parties[0].PaillierPublickey.N().BitLen())

	//tskeygen为每一个参与方生成私钥xi,yi,和公钥x^-1-1G。
	fmt.Println("tskeygen")

	start2 := time.Now()
	smt.Tskeygen(&net, SecretInfo)

	cost2 := time.Since(start2)
	fmt.Println("tskeygen cost=", cost2.Seconds())

	fmt.Println("tskeygen end")
	start3 := time.Now()
	smt.Presigning(&net, SecretInfo)

	cost3 := time.Since(start3)
	fmt.Println("presigning cost=", cost3.Seconds())

	msg := []byte("HELLO MSM2")
	net.Msg = msg

	start4 := time.Now()
	smt.Signing(&net, SecretInfo)
	cost4 := time.Since(start4)

	fmt.Println("signing cost=", cost4.Microseconds())
	R := new(big.Int).Set(net.Parties[0].R)
	S := new(big.Int).Set(net.Parties[0].S)
	party := net.Parties[0]

	newHash := HashFunc()
	Z := modfiysm2.ComputeZ(newHash, &party)
	newHash = HashFunc()
	flag := modfiysm2.Verify(C, newHash, msg, Z, party.Xx, party.Xy, R, S)
	fmt.Println("签名验证结果", flag)

	fmt.Println("main end")

	fmt.Printf("Z %x\n", Z)
	fmt.Printf("pub key Pkx %x\n", party.Xx)
	fmt.Printf("pub key Pky %x\n", party.Xy)
	fmt.Printf("sig R %x\n", R)
	fmt.Printf("sig S %x\n", S)
	fmt.Printf("msg %x\n", msg)

	var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	z, _ := sm2.CalculateZA(&ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     party.Xx,
		Y:     party.Xy,
	}, defaultUID)
	hash := HashFunc()
	// hash.Write(modfiysm2.BytesCombine(Z.Bytes(), msg))
	hash.Write(z)
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//将hash映射到椭圆曲线阶上。
	e2 := new(big.Int).SetBytes(bytes)
	e2 = e2.Mod(e2, C.Params().N)
	hash.Reset() //要养成一个良好的习惯。
	pub := ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     party.Xx,
		Y:     party.Xy,
	}

	var uid big.Int
	uid.Add(party.Rtig, party.Rho)
	fmt.Println("签名验证结果 using gmsm ", sm2.Verify(&pub, e2.Bytes(), R, S))
	fmt.Println("签名验证结果 using msm2 ", modfiysm2.Verify(C, hash, msg, new(big.Int).SetBytes(z), party.Xx, party.Xy, R, S))
	fmt.Println("签名验证结果 using gmsm ", sm2.VerifyWithSM2(&pub, nil, msg, R, S))
}

/*
	//验证签名次数为M个
	SignNum := 1
	MSignInfo := make([]smt.SignInfo, SignNum)
	party := net.Parties[0]

	start := time.Now()
	for i := 0; i < SignNum; i++ {
		smt.Presigning(&net, SecretInfo)
		msg := []byte("HELLO MSM2")
		net.Msg = msg
		smt.Signing(&net, SecretInfo)
		R := new(big.Int).Set(net.Parties[0].R)
		S := new(big.Int).Set(net.Parties[0].S)
		MSignInfo[i] = smt.SignInfo{Msg: msg, R: R, S: S}
	}

	cost := time.Since(start)
	fmt.Println("测试次数", SignNum, "cost=", cost.Seconds(), "平均时间", cost.Seconds()/float64(SignNum))

	Z := modfiysm2.ComputeZ(net.Hash, &party)

	fmt.Println("Z", Z)

	for i := 0; i < SignNum; i++ {
		flag := modfiysm2.Verify(C, net.Hash, MSignInfo[i].Msg, Z, party.Xx, party.Xy, MSignInfo[i].R, MSignInfo[i].S)
		fmt.Println("第", i, "次签名验证结果", flag)
	}
*/
