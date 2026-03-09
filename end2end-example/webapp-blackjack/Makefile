BINARY = script21

.PHONY: all local linux clean

all: local linux

local:
	go build -o $(BINARY) .

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o $(BINARY)-linux-amd64 .

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64
