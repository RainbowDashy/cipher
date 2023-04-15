package aes

import (
	"encoding/binary"
)

func encryptBlock(w []uint32, dst, src []byte) {
	s0 := binary.BigEndian.Uint32(src[0:4])
	s1 := binary.BigEndian.Uint32(src[4:8])
	s2 := binary.BigEndian.Uint32(src[8:12])
	s3 := binary.BigEndian.Uint32(src[12:16])

	s0 ^= w[0]
	s1 ^= w[1]
	s2 ^= w[2]
	s3 ^= w[3]

	nr := 10
	k := 4
	for r := 1; r < nr; r++ {
		s0, s1, s2, s3 = subBytes(s0, s1, s2, s3)
		s0, s1, s2, s3 = shiftRows(s0, s1, s2, s3)
		s0, s1, s2, s3 = mixColumns(s0, s1, s2, s3)
		s0 ^= w[k+0]
		s1 ^= w[k+1]
		s2 ^= w[k+2]
		s3 ^= w[k+3]
		k += 4
	}

	s0, s1, s2, s3 = subBytes(s0, s1, s2, s3)
	s0, s1, s2, s3 = shiftRows(s0, s1, s2, s3)
	s0 ^= w[k+0]
	s1 ^= w[k+1]
	s2 ^= w[k+2]
	s3 ^= w[k+3]

	binary.BigEndian.PutUint32(dst[0:4], s0)
	binary.BigEndian.PutUint32(dst[4:8], s1)
	binary.BigEndian.PutUint32(dst[8:12], s2)
	binary.BigEndian.PutUint32(dst[12:16], s3)
}

func decrptyBlock(w []uint32, dst, src []byte) {
	s0 := binary.BigEndian.Uint32(src[0:4])
	s1 := binary.BigEndian.Uint32(src[4:8])
	s2 := binary.BigEndian.Uint32(src[8:12])
	s3 := binary.BigEndian.Uint32(src[12:16])

	nr := 10
	k := 4 * nr
	s0 ^= w[k+0]
	s1 ^= w[k+1]
	s2 ^= w[k+2]
	s3 ^= w[k+3]

	for r := 1; r < nr; r++ {
		s0, s1, s2, s3 = invShiftRows(s0, s1, s2, s3)
		s0, s1, s2, s3 = invSubBytes(s0, s1, s2, s3)
		k -= 4
		s0 ^= w[k+0]
		s1 ^= w[k+1]
		s2 ^= w[k+2]
		s3 ^= w[k+3]
		s0, s1, s2, s3 = invMixColumns(s0, s1, s2, s3)
	}

	s0, s1, s2, s3 = invShiftRows(s0, s1, s2, s3)
	s0, s1, s2, s3 = invSubBytes(s0, s1, s2, s3)
	k -= 4
	s0 ^= w[k+0]
	s1 ^= w[k+1]
	s2 ^= w[k+2]
	s3 ^= w[k+3]

	binary.BigEndian.PutUint32(dst[0:4], s0)
	binary.BigEndian.PutUint32(dst[4:8], s1)
	binary.BigEndian.PutUint32(dst[8:12], s2)
	binary.BigEndian.PutUint32(dst[12:16], s3)
}

func subw(t uint32) uint32 {
	return uint32(sbox0[t>>24])<<24 | uint32(sbox0[t>>16&0xff])<<16 | uint32(sbox0[t>>8&0xff])<<8 | uint32(sbox0[t&0xff])
}

func rotw(t uint32) uint32 {
	return t<<8 | t>>24
}

func keyExpansion(key []byte, w []uint32) {
	if len(key) != 16 {
		panic("only support 128-bit key")
	}
	i := 0
	nk := len(key) / 4
	for ; i < nk; i++ {
		w[i] = binary.BigEndian.Uint32(key[4*i:])
	}
	for ; i < len(w); i++ {
		t := w[i-1]
		if i%nk == 0 {
			t = subw(rotw(t)) ^ rcon[i/nk]
		}
		w[i] = w[i-nk] ^ t
	}
}

func subBytes(s0, s1, s2, s3 uint32) (uint32, uint32, uint32, uint32) {
	f := func(t uint32) uint32 {
		return uint32(sbox0[t>>24])<<24 | uint32(sbox0[t>>16&0xff])<<16 | uint32(sbox0[t>>8&0xff])<<8 | uint32(sbox0[t&0xff])
	}
	return f(s0), f(s1), f(s2), f(s3)
}

func invSubBytes(s0, s1, s2, s3 uint32) (uint32, uint32, uint32, uint32) {
	f := func(t uint32) uint32 {
		return uint32(sbox1[t>>24])<<24 | uint32(sbox1[t>>16&0xff])<<16 | uint32(sbox1[t>>8&0xff])<<8 | uint32(sbox1[t&0xff])
	}
	return f(s0), f(s1), f(s2), f(s3)
}

func shiftRows(s0, s1, s2, s3 uint32) (uint32, uint32, uint32, uint32) {
	t0 := (s0>>24)<<24 | (s1>>16&0xff)<<16 | (s2>>8&0xff)<<8 | (s3 & 0xff)
	t1 := (s1>>24)<<24 | (s2>>16&0xff)<<16 | (s3>>8&0xff)<<8 | (s0 & 0xff)
	t2 := (s2>>24)<<24 | (s3>>16&0xff)<<16 | (s0>>8&0xff)<<8 | (s1 & 0xff)
	t3 := (s3>>24)<<24 | (s0>>16&0xff)<<16 | (s1>>8&0xff)<<8 | (s2 & 0xff)
	return t0, t1, t2, t3
}

func invShiftRows(s0, s1, s2, s3 uint32) (uint32, uint32, uint32, uint32) {
	t0 := (s0>>24)<<24 | (s3>>16&0xff)<<16 | (s2>>8&0xff)<<8 | (s1 & 0xff)
	t1 := (s1>>24)<<24 | (s0>>16&0xff)<<16 | (s3>>8&0xff)<<8 | (s2 & 0xff)
	t2 := (s2>>24)<<24 | (s1>>16&0xff)<<16 | (s0>>8&0xff)<<8 | (s3 & 0xff)
	t3 := (s3>>24)<<24 | (s2>>16&0xff)<<16 | (s1>>8&0xff)<<8 | (s0 & 0xff)
	return t0, t1, t2, t3
}

func mixColumns(s0, s1, s2, s3 uint32) (uint32, uint32, uint32, uint32) {
	f := func(t uint32) uint32 {
		var b0, b1, b2, b3 byte = byte(t >> 24), byte(t >> 16 & 0xff), byte(t >> 8 & 0xff), byte(t & 0xff)
		d0 := mul2[b0] ^ mul3[b1] ^ b2 ^ b3
		d1 := b0 ^ mul2[b1] ^ mul3[b2] ^ b3
		d2 := b0 ^ b1 ^ mul2[b2] ^ mul3[b3]
		d3 := mul3[b0] ^ b1 ^ b2 ^ mul2[b3]
		return binary.BigEndian.Uint32([]byte{d0, d1, d2, d3})
	}
	return f(s0), f(s1), f(s2), f(s3)
}

func invMixColumns(s0, s1, s2, s3 uint32) (uint32, uint32, uint32, uint32) {
	f := func(t uint32) uint32 {
		var b0, b1, b2, b3 byte = byte(t >> 24), byte(t >> 16 & 0xff), byte(t >> 8 & 0xff), byte(t & 0xff)
		d0 := mul14[b0] ^ mul11[b1] ^ mul13[b2] ^ mul9[b3]
		d1 := mul9[b0] ^ mul14[b1] ^ mul11[b2] ^ mul13[b3]
		d2 := mul13[b0] ^ mul9[b1] ^ mul14[b2] ^ mul11[b3]
		d3 := mul11[b0] ^ mul13[b1] ^ mul9[b2] ^ mul14[b3]
		return binary.BigEndian.Uint32([]byte{d0, d1, d2, d3})
	}
	return f(s0), f(s1), f(s2), f(s3)
}
