package tskeygen

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/lianghuiqiang9/smt/modfiysm2"
	"github.com/lianghuiqiang9/smt/network"
	"github.com/lianghuiqiang9/smt/zk"
)

type Round1Info struct {
	FromID string
	V      *big.Int
}

// 要对广播的消息，做些什么呢？
// p是收到的广播消息来自party的人。party是要处理的人
func (p *Round1Info) DoSomething(party *network.Party, net *network.Network, SecertInfo network.MSecretPartiesInfoMap) {
	//	fmt.Println(party.ID, p.FromID, p.V)
	SecertInfo[party.ID].V[p.FromID] = p.V
}

func Round1(party *network.Party, net *network.Network, SecretInfo network.MSecretPartiesInfoMap, wg *sync.WaitGroup) {
	defer wg.Done()
	//生成私钥和随机数gamma
	xi, _ := modfiysm2.RandFieldElement(party.Curve, nil)
	gammai, _ := modfiysm2.RandFieldElement(party.Curve, nil)
	Xix, Xiy := party.Curve.ScalarBaseMult(xi.Bytes())
	Gammaix, Gammaiy := party.Curve.ScalarBaseMult(gammai.Bytes())
	//生成随机数rhoi，ui
	bf := make([]byte, 32)
	rand.Read(bf)
	rhoi := new(big.Int).SetBytes(bf)

	bf2 := make([]byte, 32)
	rand.Read(bf2)
	ui := new(big.Int).SetBytes(bf2)
	//计算Vi
	net.Mtx.Lock()
	net.Hash.Write(zk.BytesCombine(party.Rtig.Bytes(), Xix.Bytes(), Xiy.Bytes(), Gammaix.Bytes(), Gammaiy.Bytes(), rhoi.Bytes(), ui.Bytes()))
	bytes := net.Hash.Sum(nil)
	//计算hash承诺
	Vi := new(big.Int).SetBytes(bytes)
	//	fmt.Println("Vi", Vi, party.Rtig, Xix, Xiy, Gammaix, Gammaiy, rhoi, ui)
	net.Hash.Reset()
	net.Mtx.Unlock()

	//将秘密信息读入
	SecretInfo[party.ID].Xi = xi
	SecretInfo[party.ID].Gammai = gammai
	SecretInfo[party.ID].Xix = Xix
	SecretInfo[party.ID].Xiy = Xiy
	SecretInfo[party.ID].Gammaix = Gammaix
	SecretInfo[party.ID].Gammaiy = Gammaiy
	SecretInfo[party.ID].Rhoi = new(big.Int).SetBytes(bf)
	SecretInfo[party.ID].Ui = ui
	//最好还是new一个吧，万一呢

	//将hash值广播出去
	Round1Content := Round1Info{party.ID, Vi}
	Msg := network.Message{FromID: party.ID, ToID: "", MContent: &Round1Content}
	//广播消息
	for _, mparty := range net.Parties {
		//本地计算消息位置2，向每一个参与方广播不同消息使用
		if mparty.ID != party.ID {
			Msg.ToID = mparty.ID
			net.Channels[mparty.ID] <- &Msg
		}
	}
	//Round1结束
}
