package ecdhtest

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestECDHWrongOddness(t *testing.T) {
	var err error
	var sk1, sk2 *btcec.PrivateKey
	var pk1, pk2 *btcec.PublicKey
	var pkb1, pkb2, mpkb1, mpkb2, sb1, sb2 []byte
	var mpk1, mpk2 *btcec.PublicKey
	for _ = range 100 {
		if sk1, err = btcec.NewPrivateKey(); err != nil {
			t.Error(err)
		}
		pk1 = sk1.PubKey()
		pkb1 = pk1.SerializeCompressed()
		if sk2, err = btcec.NewPrivateKey(); err != nil {
			t.Error(err)
		}
		pk2 = sk2.PubKey()
		pkb2 = pk2.SerializeCompressed()
		if mpk1, err = secp256k1.ParsePubKey(append([]byte{0x02}, pkb1[1:]...)); err != nil {
			return
		}
		if mpk2, err = secp256k1.ParsePubKey(append([]byte{0x02}, pkb2[1:]...)); err != nil {
			return
		}
		mpkb1 = mpk1.SerializeCompressed()
		mpkb2 = mpk2.SerializeCompressed()
		sb1 = sk1.Serialize()
		sb2 = sk2.Serialize()
		ecdhab := btcec.GenerateSharedSecret(sk1, pk2)
		ecdhba := btcec.GenerateSharedSecret(sk2, pk1)
		ecdhbA := btcec.GenerateSharedSecret(sk1, mpk2)
		ecdhaB := btcec.GenerateSharedSecret(sk2, mpk1)
		// if !bytes.Equal(ecdhab, ecdhba) || !bytes.Equal(ecdhaB, ecdhbA) {
		if pkb1[0] == 3 || pkb2[0] == 3 {
			t.Logf(
				"\nsa %0x | pa %0x = ECDHab %0x"+
					"\nsb %0x | pb %0x = ECDHba %0x"+
					"\nsa %0x | pA %0x = ECDHaB %0x"+
					"\nsb %0x | pB %0x = ECDHbA %0x",
				sb1, pkb1, ecdhab,
				sb2, pkb2, ecdhba,
				sb1, mpkb1, ecdhaB,
				sb2, mpkb2, ecdhbA,
			)
		}
		// }
	}
}
