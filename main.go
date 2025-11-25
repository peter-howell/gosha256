package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/peter-howell/gosha256/internal/gosha256"
)

// main computes and prints the SHA-256 digest of the first
// command-line argument. It performs message padding, processes
// the message in 512-bit chunks using the SHA-256 compression
// function, and prints the 32-byte digest in hexadecimal.
func main() {
	var conn io.Reader
	var err error
	if len(os.Args) < 2 {
		fmt.Println("didn't receive an argument, using stdin")
		conn = bufio.NewReader(os.Stdin)
		result := gosha256.SHA256Sum(conn)

		// Pad the message to proper length
		fmt.Printf("%x  -\n", *result)
	} else {
		// take the message from a cmd line argument and store it as a byte array
		for i := 1; i < len(os.Args); i++ {
			fname := os.Args[i]
			conn, err = os.Open(fname)

			if err != nil {
				fmt.Printf("Got an error trying to open %s, %v\n", fname, err)
				continue
			}
			result := gosha256.SHA256Sum(conn)

			// Pad the message to proper length
			fmt.Printf("%x  %s\n", *result, fname)
		}
	}


}

