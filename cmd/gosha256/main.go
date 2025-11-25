package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/peter-howell/gosha256/sha256"
)

func main() {
	var conn io.Reader
	var err error
	if len(os.Args) < 2 {
		fmt.Println("didn't receive an argument, using stdin")
		conn = bufio.NewReader(os.Stdin)
		result := sha256.SHA256Sum(conn)

		// Pad the message to proper length
		fmt.Printf("%x  -\n", *result)
	} else {
		// take file names from command-line arguments
		for i := 1; i < len(os.Args); i++ {
			fname := os.Args[i]
			conn, err = os.Open(fname)

			if err != nil {
				fmt.Printf("Got an error trying to open %s, %v\n", fname, err)
				continue
			}
			result := sha256.SHA256Sum(conn)

			// Pad the message to proper length
			fmt.Printf("%x  %s\n", *result, fname)
		}
	}


}

