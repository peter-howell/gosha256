package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
)

// rightrotate rotates the 32-bit unsigned integer `x` right by `k` bits.
// `k` is reduced modulo 32 before rotation. The function uses
// `bits.RotateLeft32` with `32-k` to implement a right rotation.
func rightrotate(x uint32, k int) uint32 {
	k = k % 32
	return bits.RotateLeft32(x, 32-k)

}

type Hasher struct {
	h [8]uint32
	words [64]uint32
}

func NewHasher() *Hasher {
	return &Hasher{
		h: [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
		words: [64]uint32{},
	}
}

var h0 uint32 = 0x6a09e667
var h1 uint32 = 0xbb67ae85
var h2 uint32 = 0x3c6ef372
var h3 uint32 = 0xa54ff53a
var h4 uint32 = 0x510e527f
var h5 uint32 = 0x9b05688c
var h6 uint32 = 0x1f83d9ab
var h7 uint32 = 0x5be0cd19

var k []uint32 = []uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// getWords converts the byte slice `data` into big-endian `uint32` words
// and writes them into the provided `out` slice. It returns the number
// of words written. The function reads 4 bytes at a time; any final
// partial chunk (less than 4 bytes) is ignored.
func getWords(data *[64]byte, words *[64]uint32) {
	for i := range 16 {
		words[i] = binary.BigEndian.Uint32(data[4*i : 4*i+4])
	}
}


func processChunk(chunk *[64]byte, words *[64]uint32) error {

	// convert each 4 bytes into a uint32. Store them in here.
	getWords(chunk, words)

	a := h0
	b := h1
	c := h2
	d := h3
	e := h4
	f := h5
	g := h6
	h := h7

	//extend the first 16 words into the remaining 48 words
	for i := 16; i < 64; i++ {
		s0 := rightrotate(words[i-15], 7) ^ rightrotate(words[i-15], 18) ^ (words[i-15] >> 3)
		s1 := rightrotate(words[i-2], 17) ^ rightrotate(words[i-2], 19) ^ (words[i-2] >> 10)
		words[i] = words[i-16] + s0 + words[i-7] + s1
	}
	// compression function main loop:
	for i := range 64 {
		S1 := rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
		ch := (e & f) ^ (^e & g)
		temp1 := h + S1 + ch + k[i] + words[i]
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
	h0 = h0 + a
	h1 = h1 + b
	h2 = h2 + c
	h3 = h3 + d
	h4 = h4 + e
	h5 = h5 + f
	h6 = h6 + g
	h7 = h7 + h

	return nil

}

// SHA256Sum computes the SHA-256 hash of a byte array.
func SHA256Sum(msg []byte) [32]byte {
	ogBitLen := uint64(len(msg) * 8)         // original message length in bits
	neededLenBits := ogBitLen + 1            // add the following 1 bit
	K := (448 - (neededLenBits % 512)) % 512 // add 0 bits until len %512 = 448
	neededLenBits += K + 64                  // with the uint64 of the length.

	message := make([]byte, neededLenBits/8) // message as an array of bytes, padded correctly
	copy(message, msg)

	message[len(msg)] = 0x80
	binary.BigEndian.PutUint64(message[(neededLenBits/8)-8:], ogBitLen) // length of original message at the end

	buf := bytes.NewBuffer(message)

	words := [64]uint32{}
	chunk := [64]byte{}

	for {
		// chunk of 512 bits (64 bytes)
		// chunk := buf.Next(64)
		n, err := buf.Read(chunk[:])
		fmt.Printf("Read %d bytes\n", n)
		if n == 0 {
			break
		}
		if err != nil {
			fmt.Printf("Got some error, %v", err)
			break
		}
		processChunk(&chunk, &words)
	}

	result := [32]byte{}
	binary.BigEndian.PutUint32(result[0:], h0)
	binary.BigEndian.PutUint32(result[4:], h1)
	binary.BigEndian.PutUint32(result[8:], h2)
	binary.BigEndian.PutUint32(result[12:], h3)
	binary.BigEndian.PutUint32(result[16:], h4)
	binary.BigEndian.PutUint32(result[20:], h5)
	binary.BigEndian.PutUint32(result[24:], h6)
	binary.BigEndian.PutUint32(result[28:], h7)
	return result
}

// main computes and prints the SHA-256 digest of the first
// command-line argument. It performs message padding, processes
// the message in 512-bit chunks using the SHA-256 compression
// function, and prints the 32-byte digest in hexadecimal.
func main() {
	if len(os.Args) < 2 {
		fmt.Println("didn't receive an argument. there should be an argument here.")
		return
	}
	// take the message from a cmd line argument and store it as a byte array
	msg := []byte(os.Args[1])

	result := SHA256Sum(msg)

	// Pad the message to proper length
	fmt.Printf("Result:\n%x\n", result)
}

