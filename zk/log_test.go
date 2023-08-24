package zk

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestLog(t *testing.T) {
	priv, _ := sm2.GenerateKey()

	hash := sha256.New()

	logp := LogProve(hash, priv.Curve, priv.X, priv.Y, priv.D)

	tt, err := logp.MarshalBinary()
	if err != nil {
		fmt.Println(err)
	}
	var logp2 Logp
	err = logp2.UnmarshalBinary(tt)
	if err != nil {
		fmt.Println(err)
	}

	flag := logp2.LogVerify(hash, priv.Curve, priv.X, priv.Y)
	fmt.Println(flag)
}
