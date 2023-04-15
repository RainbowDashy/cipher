package maes

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestGuess(t *testing.T) {
	a := require.New(t)
	plaintext := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f,
	}

	trcon := make([]uint32, 10)
	tweak := []byte("this is a tweak")
	rt := make([]byte, 4*len(trcon))
	sh := sha3.NewShake256()
	sh.Write(tweak)
	sh.Read(rt)
	for i := range trcon {
		trcon[i] = binary.BigEndian.Uint32(rt[4*i:])
	}
	wk := make([]uint32, 44)
	wt := make([]uint32, 40)
	keyExpansion(key, wk)
	tweakExpansion(tweak, trcon, wt)

	a.Equal(wt[0], wt[1])
	a.Equal(wt[0], wt[2])
	a.Equal(wt[0], wt[3])

	encrypted := make([]byte, len(plaintext))
	decrypted := make([]byte, len(plaintext))

	encryptBlock(wk, wt, encrypted, plaintext)
	decrptyBlock(wk, wt, decrypted, encrypted)
	a.Equal(plaintext, decrypted)

	guessA := uint32(0xb594aee9)
	res := guess(plaintext, encrypted, tweak, trcon, uint32(guessA))
	a.Equal(res, key)
}

func TestGuessKey(t *testing.T) {
	a := require.New(t)
	plaintext := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f,
	}

	trcon := make([]uint32, 10)
	tweak := []byte("this is a tweak")
	rt := make([]byte, 4*len(trcon))
	sh := sha3.NewShake256()
	sh.Write(tweak)
	sh.Read(rt)
	for i := range trcon {
		trcon[i] = binary.BigEndian.Uint32(rt[4*i:])
	}
	wk := make([]uint32, 44)
	wt := make([]uint32, 40)
	keyExpansion(key, wk)
	tweakExpansion(tweak, trcon, wt)

	a.Equal(wt[0], wt[1])
	a.Equal(wt[0], wt[2])
	a.Equal(wt[0], wt[3])

	encrypted := make([]byte, len(plaintext))
	decrypted := make([]byte, len(plaintext))

	encryptBlock(wk, wt, encrypted, plaintext)
	decrptyBlock(wk, wt, decrypted, encrypted)
	a.Equal(plaintext, decrypted)

	res := guessKey(plaintext, encrypted, tweak, trcon)
	a.Equal(res, key)
}

func BenchmarkGuess(b *testing.B) {
	plaintext := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f,
	}

	trcon := make([]uint32, 10)
	tweak := []byte("this is a tweak")
	rt := make([]byte, 4*len(trcon))
	sh := sha3.NewShake256()
	sh.Write(tweak)
	sh.Read(rt)
	for i := range trcon {
		trcon[i] = binary.BigEndian.Uint32(rt[4*i:])
	}
	wk := make([]uint32, 44)
	wt := make([]uint32, 40)
	keyExpansion(key, wk)
	tweakExpansion(tweak, trcon, wt)
	encrypted := make([]byte, len(plaintext))
	decrypted := make([]byte, len(plaintext))

	encryptBlock(wk, wt, encrypted, plaintext)
	decrptyBlock(wk, wt, decrypted, encrypted)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = guess(plaintext, encrypted, tweak, trcon, uint32(i))
	}
}
