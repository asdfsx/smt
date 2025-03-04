package paillier

import (
	"crypto/rand"
	"math/big"

	"github.com/cronokirby/saferith"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
)

// Ciphertext represents an integer of the for (1+N)ᵐρᴺ (mod N²), representing the encryption of m ∈ ℤₙˣ.
type Ciphertext struct {
	c    *saferith.Nat
	cbig *big.Int //cbig只用于测试bigInt的paillier和saferithInt.Nat的paillier加密速度，对于协议无用
}

// Add sets ct to the homomorphic sum ct ⊕ ct₂.
// ct ← ct•ct₂ (mod N²).
func (ct *Ciphertext) Add(pk *PublicKey, ct2 *Ciphertext) *Ciphertext {
	if ct2 == nil {
		return ct
	}

	ct.c.ModMul(ct.c, ct2.c, pk.nSquared.Modulus)

	return ct
}

func (cipher1 *Ciphertext) AddCipher(pk *PublicKey, cipher2 *Ciphertext) *Ciphertext {
	x := cipher1.cbig
	y := cipher2.cbig

	// x * y mod n^2
	return &Ciphertext{cbig: new(big.Int).Mod(
		new(big.Int).Mul(x, y),
		pk.NSquared,
	)}
}

func (cipher *Ciphertext) Mul1(pk *PublicKey, constant *big.Int) *Ciphertext {
	c := cipher.cbig
	x := constant
	// c ^ x mod n^2
	return &Ciphertext{cbig: new(big.Int).Exp(c, x, pk.NSquared)}
}

// Mul sets ct to the homomorphic multiplication of k ⊙ ct.
// ct ← ctᵏ (mod N²).
func (ct *Ciphertext) Mul(pk *PublicKey, k *saferith.Int) *Ciphertext {
	if k == nil {
		return ct
	}
	c := ct.c.Big()
	x := k.Big()
	cbig := new(big.Int).Exp(c, x, pk.NSquared)
	csafenat := new(saferith.Nat).SetBig(cbig, cbig.BitLen())

	return &Ciphertext{c: csafenat}
}

// Equal check whether ct ≡ ctₐ (mod N²).
func (ct *Ciphertext) Equal(ctA *Ciphertext) bool {
	return ct.c.Eq(ctA.c) == 1
}

// Clone returns a deep copy of ct.
func (ct Ciphertext) Clone() *Ciphertext {
	c := new(saferith.Nat)
	c.SetNat(ct.c)
	return &Ciphertext{c: c}
}

// Randomize multiplies the ciphertext's nonce by a newly generated one.
// ct ← ct ⋅ nonceᴺ (mod N²).
// If nonce is nil, a random one is generated.
// The receiver is updated, and the nonce update is returned.
func (ct *Ciphertext) Randomize(pk *PublicKey, nonce *saferith.Nat) *saferith.Nat {
	if nonce == nil {
		nonce = sample.UnitModN(rand.Reader, pk.n.Modulus)
	}
	// c = c*r^N
	tmp := pk.nSquared.Exp(nonce, pk.nNat)
	ct.c.ModMul(ct.c, tmp, pk.nSquared.Modulus)
	return nonce
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
//func (ct *Ciphertext) WriteTo(w io.Writer) (int64, error) {
//	if ct == nil {
//		return 0, io.ErrUnexpectedEOF
//	}
//	buf := make([]byte, params.BytesCiphertext)
//	ct.c.FillBytes(buf)
//	n, err := w.Write(buf)
//	return int64(n), err
//}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (*Ciphertext) Domain() string {
	return "Paillier Ciphertext"
}

func (ct *Ciphertext) MarshalBinary() ([]byte, error) {
	return ct.c.MarshalBinary()
}

func (ct *Ciphertext) UnmarshalBinary(data []byte) error {
	ct.c = new(saferith.Nat)
	return ct.c.UnmarshalBinary(data)
}

func (ct *Ciphertext) Nat() *saferith.Nat {
	return new(saferith.Nat).SetNat(ct.c)
}
