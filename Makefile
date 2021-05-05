all:
	protoc -I=. --go_out=. tracecap.proto
	go generate ./...
	go build
