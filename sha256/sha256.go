// Package sha256 implements the SHA-256 algorithm
package sha256

import (
	"encoding/binary"
	"io"
	"math/bits"
)

const ChunkBytes = 64

var k [64]uint32 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// rightrotate rotates the 32-bit unsigned integer `x` right by `k` bits.
// `k` is reduced modulo 32 before rotation. The function uses
// `bits.RotateLeft32` with `32-k` to implement a right rotation.
func rightrotate(x uint32, k int) uint32 {
	k = k % 32
	return bits.RotateLeft32(x, 32-k)

}

type Hasher struct {
	h [8]uint32 // hash values
	words [64]uint32 // storage for the words
	chunkBuf [ChunkBytes]byte
	nBitsRead uint64 // number of bits read so far
	chunkLen int
}

func NewHasher() *Hasher {
	return &Hasher{
		h: [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
		words: [64]uint32{},
		chunkBuf: [ChunkBytes]byte{},
		nBitsRead: 0,
		chunkLen: 0,
	}
}

// getWords converts the 64 byte message into 16 big-endian `uint32` words
func (hasher *Hasher) getWords() {
	for i := range 16 {
		hasher.words[i] = binary.BigEndian.Uint32(hasher.chunkBuf[4*i : 4*i + 4])
	}
}

func (hasher *Hasher) processChunk() {
	// convert each 4 bytes into a uint32. Store them in here.
	hasher.getWords()

	a := hasher.h[0]
	b := hasher.h[1]
	c := hasher.h[2]
	d := hasher.h[3]
	e := hasher.h[4]
	f := hasher.h[5]
	g := hasher.h[6]
	h := hasher.h[7]

	//extend the first 16 words into the remaining 48 words
	for i := 16; i < ChunkBytes; i++ {
		s0 := rightrotate(hasher.words[i-15], 7) ^ rightrotate(hasher.words[i-15], 18) ^ (hasher.words[i-15] >> 3)
		s1 := rightrotate(hasher.words[i-2], 17) ^ rightrotate(hasher.words[i-2], 19) ^ (hasher.words[i-2] >> 10)
		hasher.words[i] = hasher.words[i-16] + s0 + hasher.words[i-7] + s1
	}
	// compression function main loop:
	for i := range ChunkBytes {
		S1 := rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
		ch := (e & f) ^ (^e & g)
		temp1 := h + S1 + ch + k[i] + hasher.words[i]
		S0 := rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := S0 + maj

		h = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}
	// add the compressed chunk to the current hash value
	hasher.h[0] = hasher.h[0] + a
	hasher.h[1] = hasher.h[1] + b
	hasher.h[2] = hasher.h[2] + c
	hasher.h[3] = hasher.h[3] + d
	hasher.h[4] = hasher.h[4] + e
	hasher.h[5] = hasher.h[5] + f
	hasher.h[6] = hasher.h[6] + g
	hasher.h[7] = hasher.h[7] + h

}

func (hasher *Hasher) Write(buf []byte) (int, error) {
	n := len(buf)
	for len(buf) > 0 {
		nAdded := copy(hasher.chunkBuf[hasher.chunkLen:], buf)
		hasher.chunkLen += nAdded
		buf = buf[nAdded:]
		if hasher.chunkLen == ChunkBytes {
			hasher.processChunk()
			hasher.nBitsRead += uint64(512)
			hasher.chunkLen = 0
		}
	}
	return n, nil
}

func (hasher *Hasher) Sum() [32]byte {
	hasher.nBitsRead += uint64(8 * hasher.chunkLen)
	hasher.chunkBuf[hasher.chunkLen] = 0x80
	for i := hasher.chunkLen+1; i < ChunkBytes; i++ {
		hasher.chunkBuf[i] = 0
	}

	if hasher.chunkLen > ChunkBytes - 9 {
		hasher.processChunk()
		hasher.chunkBuf = [ChunkBytes]byte{}
	}
	binary.BigEndian.PutUint64(hasher.chunkBuf[ChunkBytes - 8:], hasher.nBitsRead)
	hasher.processChunk()

	result := [32]byte{}
	binary.BigEndian.PutUint32(result[0:], hasher.h[0])
	binary.BigEndian.PutUint32(result[4:], hasher.h[1])
	binary.BigEndian.PutUint32(result[8:], hasher.h[2])
	binary.BigEndian.PutUint32(result[12:], hasher.h[3])
	binary.BigEndian.PutUint32(result[16:], hasher.h[4])
	binary.BigEndian.PutUint32(result[20:], hasher.h[5])
	binary.BigEndian.PutUint32(result[24:], hasher.h[6])
	binary.BigEndian.PutUint32(result[28:], hasher.h[7])
	return result
}

// SHA256Sum computes the SHA-256 hash of a message of bytes read from a reader 
func SHA256Sum(conn io.Reader) [32]byte {
	hasher := NewHasher()
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if n == 0 {
			break
		}
		if err != nil {
			break
		}
		hasher.Write(buf[:n])
	}
	return hasher.Sum()
}

