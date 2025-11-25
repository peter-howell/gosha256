BINARY_NAME=gosha256

build:
	go build -o ${BINARY_NAME} ./cmd/gosha256

test: ${BINARY_NAME}
	grep "Len = " SHA256LongMsg.rsp | sed 's/Len = //' > message-sizes.txt
	python prep_test_binaries.py
	go test ./...

