package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/peter-howell/gosha256/sha256"
	"github.com/stretchr/testify/assert"
)

const NFiles = 64
const HexStringHashLen = 64

func loadKnownValues() ([][]byte, []string, error) {

	sizes := make([]int, NFiles)
	f, err := os.Open("message-sizes.txt")
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	lineNum := 0
	for scanner.Scan() {
		bitLen, err := strconv.Atoi(scanner.Text())
		if err != nil {
			return nil, nil, err
		}
		sizes[lineNum] = bitLen / 8 // byte length
		lineNum ++

	}
	msgs := make([][]byte, NFiles)
	hashes := make([]string, NFiles)
	tempHash := make([]byte, HexStringHashLen)

	for i := range NFiles {
		msgF, hashF := fmt.Sprintf("messages/msg%d", i), fmt.Sprintf("hashes/hash%d", i)
		msgFile, err := os.Open(msgF)
		if err != nil {
			return nil, nil, err
		}

		nBytes := sizes[i]
		msgs[i] = make([]byte, nBytes)
		n, err := msgFile.Read(msgs[i])
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		msgFile.Close()
		if n != nBytes {
			return nil, nil, fmt.Errorf("expecting %d bytes, but got %d bytes for %s", nBytes, n, msgF)
		}

		hashFile, err := os.Open(hashF)
		if err != nil {
			return nil, nil, err
		}
		n, err = hashFile.Read(tempHash)
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		hashes[i] = string(tempHash[:n])
		hashFile.Close()
		if n != 64 {
			return nil, nil, fmt.Errorf("expecting 32 byte hash, but got %d bytes for %s", n, hashF)
		}
	}
	return msgs, hashes, nil

}

func TestSum256_KnownVectors(t *testing.T) {

	msgs, hashes, err := loadKnownValues()
	assert.Nil(t, err)
	for i := range NFiles {
		msg := msgs[i]
		hasher := sha256.NewHasher()
		hasher.Write(msg)
		got := hasher.Sum()
		want := hashes[i]
		assert.Equal(t, want, fmt.Sprintf("%x", got))
	}
}

