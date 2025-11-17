package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
)


func rightrotate(x uint32, k int) uint32 {
	k = k % 32
	return bits.RotateLeft32(x, 32 - k)

}

var h0 uint32 = 0x6a09e667
var h1 uint32 = 0xbb67ae85
var h2 uint32 = 0x3c6ef372
var h3 uint32 = 0xa54ff53a
var h4 uint32 = 0x510e527f
var h5 uint32 = 0x9b05688c
var h6 uint32 = 0x1f83d9ab
var h7 uint32 = 0x5be0cd19

var k []uint32 = []uint32 {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func toUInt(data []byte, out []uint32) int {
	buf := bytes.NewBuffer(data)
	nOut := 1 + (len(data) / 4)
	i := 0
	for {
		x := buf.Next(4)
		if len(x) == 0 {
			break
		}
		out[i] = binary.BigEndian.Uint32(x)
		i += 1

	}
	fmt.Printf("i: %d, nOut: %d", i, nOut)
	return i
}

func main() {
	message := []byte(os.Args[1])
	messageLen := len(message)

	buf := bytes.NewBuffer(message)
	
	nIter := 1 + ((messageLen * 8) / 512)
	for x := range nIter {
		// chunk of 512 bits (64 bytes)
		data := buf.Next(64)
		// set of 64 uint32 items.
		w := make([]uint32, 64)
		// convert each 4 bytes into a uint32. Store them in here.
		nWordsInData := toUInt(data, w)

		if nWordsInData < 16 {
			fmt.Printf("Only received %d bytes, was hoping for 16\n", nWordsInData)
			fmt.Printf("We are on loop %d and should be on loop %d\n", x, nIter)
			// fill the rest with a single '1' bit and then the rest are zeros
			tem := make([]byte, 2)// stores the value 0x10
			binary.BigEndian.PutUint16(tem, uint16(8))
			w[nWordsInData] = binary.BigEndian.Uint32(tem)// convert the 0x10 to uint32
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4
		f := h5
		g := h6
		h := h7

		//extend the first 16 words into the remaining 48 words
		for i := 16; i <64; i++ {
			s0 := rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ (w[i-15] >> 3)
			s1 := rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ (w[i-2] >> 2)
			w[i] = w[i-16] + s0 + w[i-7] + s1

		}

		// compression function main loop:
		for i := range 64 {
			S1 := rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
			ch := (e & f) ^ (^e  & g)
			temp1 := h + S1 + ch + k[i] + w[i]
			S0 := rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)
			maj := (a & b) ^ (a & c) ^ (a & c)
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
		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
		h5 = h5 + f
		h6 = h6 + g
		h7 = h7 + h
	}

	result := make([]byte, 32)
	binary.BigEndian.PutUint32(result, h0)
	binary.BigEndian.PutUint32(result[4:], h1)
	binary.BigEndian.PutUint32(result[8:], h2)
	binary.BigEndian.PutUint32(result[12:], h3)
	binary.BigEndian.PutUint32(result[16:], h4)
	binary.BigEndian.PutUint32(result[20:], h5)
	binary.BigEndian.PutUint32(result[24:], h6)
	binary.BigEndian.PutUint32(result[28:], h7)
	fmt.Printf("Result:\n%x\n", result)

}
