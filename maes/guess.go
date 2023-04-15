package maes

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

func guessKey(plaintext, ciphertext, tweak []byte, trcon []uint32) []byte {
	ctx, cancel := context.WithCancel(context.Background())
	resChan := make(chan []byte, 1)
	for i := 0; i < 16; i++ {
		go guessPart(ctx, resChan, plaintext, ciphertext, tweak, trcon, i)
	}
	key := <-resChan
	cancel()
	close(resChan)
	return key
}

func guessPart(ctx context.Context, resChan chan<- []byte, plaintext, ciphertext, tweak []byte, trcon []uint32, idx int) {
	a0 := uint32(idx << 28)
	a1 := uint32(0)
	for {
		if ctx.Err() != nil {
			return
		}
		a := a0 | a1
		key := guess(plaintext, ciphertext, tweak, trcon, a)
		if key != nil {
			resChan <- key
			return
		}
		a1++
		if a1&0xf0000000 != 0 {
			break
		}

		if a1%0xfffffff == 0 {
			fmt.Printf("idx %d: finishing %d\n", idx, a1/0xfffffff)
		}
	}
}

func guess(plaintext, ciphertext, tweak []byte, trcon []uint32, a uint32) []byte {
	a0, a1, a2, a3 := byte(a>>24), byte(a>>16&0xff), byte(a>>8&0xff), byte(a&0xff)
	wk := make([]uint32, 13)
	wk[9] = uint32(a0^sbox1[ciphertext[0]])<<24 | uint32(a1^sbox1[ciphertext[13]])<<16 | uint32(a2^sbox1[ciphertext[10]])<<8 | uint32(a3^sbox1[ciphertext[7]])
	wk[10] = uint32(a0^sbox1[ciphertext[4]])<<24 | uint32(a1^sbox1[ciphertext[1]])<<16 | uint32(a2^sbox1[ciphertext[14]])<<8 | uint32(a3^sbox1[ciphertext[11]])
	wk[11] = uint32(sbox0[a0]^ciphertext[8])<<24 | uint32(sbox0[a1]^ciphertext[5])<<16 | uint32(sbox0[a2]^ciphertext[2])<<8 | uint32(sbox0[a3]^ciphertext[15])
	wk[12] = uint32(sbox0[a0]^ciphertext[12])<<24 | uint32(sbox0[a1]^ciphertext[9])<<16 | uint32(sbox0[a2]^ciphertext[6])<<8 | uint32(sbox0[a3]^ciphertext[3])
	for i := 8; i >= 0; i-- {
		if i%4 == 0 {
			wk[i] = wk[i+4] ^ subw(rotw(wk[i+3])) ^ rcon[(i+4)/4]
		} else {
			wk[i] = wk[i+4] ^ wk[i+3]
		}
	}

	key := make([]byte, 16)
	binary.BigEndian.PutUint32(key[0:4], wk[0])
	binary.BigEndian.PutUint32(key[4:8], wk[1])
	binary.BigEndian.PutUint32(key[8:12], wk[2])
	binary.BigEndian.PutUint32(key[12:16], wk[3])

	if checkKey(plaintext, ciphertext, tweak, trcon, key) {
		return key
	}
	return nil
}

func checkKey(plaintext, ciphertext, tweak []byte, trcon []uint32, key []byte) bool {
	wk := make([]uint32, 44)
	wt := make([]uint32, 40)
	encrypted := make([]byte, len(plaintext))
	keyExpansion(key, wk)
	tweakExpansion(tweak, trcon, wt)
	encryptBlock(wk, wt, encrypted, plaintext)
	return bytes.Equal(encrypted, ciphertext)
}
