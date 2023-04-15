package maes

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSubBytes(t *testing.T) {
	a := require.New(t)
	var a0, a1, a2, a3 uint32 = 0x12345678, 0x87654321, 0xabcd1234, 0x3f1e2a4b
	b0, b1, b2, b3 := subBytes(a0, a1, a2, a3)
	c0, c1, c2, c3 := invSubBytes(b0, b1, b2, b3)
	a.Equal(a0, c0)
	a.Equal(a1, c1)
	a.Equal(a2, c2)
	a.Equal(a3, c3)
}

func TestShiftRows(t *testing.T) {
	a := require.New(t)
	var a0, a1, a2, a3 uint32 = 0x12345678, 0x87654321, 0xabcd1234, 0x3f1e2a4b
	b0, b1, b2, b3 := shiftRows(a0, a1, a2, a3)
	c0, c1, c2, c3 := invShiftRows(b0, b1, b2, b3)
	a.Equal(a0, c0)
	a.Equal(a1, c1)
	a.Equal(a2, c2)
	a.Equal(a3, c3)
}

func TestMixColumns(t *testing.T) {
	a := require.New(t)
	var a0, a1, a2, a3 uint32 = 0x12345678, 0x87654321, 0xabcd1234, 0x3f1e2a4b
	b0, b1, b2, b3 := mixColumns(a0, a1, a2, a3)
	c0, c1, c2, c3 := invMixColumns(b0, b1, b2, b3)
	a.Equal(a0, c0)
	a.Equal(a1, c1)
	a.Equal(a2, c2)
	a.Equal(a3, c3)
}

func TestKeyExpansion(t *testing.T) {
	a := require.New(t)
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	w := make([]uint32, 44)
	keyExpansion(key, w)
	a.Equal(uint32(0x2b7e1516), w[0])
	a.Equal(uint32(0x28aed2a6), w[1])
	a.Equal(uint32(0xabf71588), w[2])
	a.Equal(uint32(0x09cf4f3c), w[3])
	a.Equal(uint32(0xa0fafe17), w[4])
}

func TestTweakExpansion(t *testing.T) {
	a := require.New(t)
	trcon := make([]uint32, 10)
	for i := range trcon {
		trcon[i] = uint32(i)
	}
	wt := make([]uint32, 40)
	tweakExpansion([]byte("this is a tweak"), trcon, wt)
	a.Equal(wt[0], uint32(0))
	a.Equal(wt[1], uint32(0))
	a.Equal(wt[2], uint32(0x9a5eb1ff))
	a.Equal(wt[3], uint32(0x9a5eb1ff))
	a.Equal(wt[4], uint32(1))
	a.Equal(wt[5], uint32(1))
	a.Equal(wt[6], uint32(0x4733898b))
	a.Equal(wt[7], uint32(0x4733898b))

}

func TestCipher(t *testing.T) {
	a := require.New(t)
	plaintext := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
		0xee, 0xff,
	}
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f,
	}
	ciphertext := []byte{
		0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
		0xc5, 0x5a,
	}
	wk := make([]uint32, 44)
	wt := make([]uint32, 40)
	dst := make([]byte, len(plaintext))
	keyExpansion(key, wk)
	encryptBlock(wk, wt, dst, plaintext)
	a.Equal(ciphertext, dst)
	decrptyBlock(wk, wt, dst, ciphertext)
	a.Equal(plaintext, dst)
}

func TestTweakedCipher(t *testing.T) {
	a := require.New(t)
	rg := rand.New(rand.NewSource(time.Now().UnixNano()))
	plaintext := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
		0xee, 0xff,
	}
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f,
	}

	trcon := make([]uint32, 10)
	for i := range trcon {
		trcon[i] = rg.Uint32()
	}
	wk := make([]uint32, 44)
	wt := make([]uint32, 40)
	keyExpansion(key, wk)
	tweakExpansion([]byte("this is a tweak"), trcon, wt)

	encrypted := make([]byte, len(plaintext))
	decrypted := make([]byte, len(plaintext))

	encryptBlock(wk, wt, encrypted, plaintext)
	decrptyBlock(wk, wt, decrypted, encrypted)
	a.Equal(plaintext, decrypted)
}
