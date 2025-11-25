package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func loadKnownValues() ([][]byte, []string, error) {
	const nFiles = 64

	sizes := make([]int, nFiles)
	f, err := os.Open("message-sizes.txt")
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	lineNum := 0
	for scanner.Scan() {
		sizes[lineNum], err = strconv.Atoi(scanner.Text())
		if err != nil {
			return nil, nil, err
		}
		sizes[lineNum] = sizes[lineNum] / 8
		lineNum ++

	}
	msgs := make([][]byte, nFiles)
	hashes := make([]string, nFiles)
	tempHash := make([]byte, 64)

	for i := range nFiles {
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
	for i := range 10 {
		fmt.Printf("msg %d is :%x\n", i, msgs[i])
		got := SHA256Sum(bytes.NewBuffer(msgs[i]))
		want := hashes[i]
		assert.Equal(t, want, fmt.Sprintf("%x", string(got[:])))
	}
}

