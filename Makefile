BINARY_NAME=my-sha256

build:
	go build -o ${BINARY_NAME} main.go

test: ${BINARY_NAME}
	grep "Len = " SHA256LongMsg.rsp | sed 's/Len = //' > message-sizes.txt
	python prep_test_binaries.py
	go test .
