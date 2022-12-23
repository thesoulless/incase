
default: test

.PHONY: test
test: fuzz
	go test --race ./...

fuzz:
	go test -v -fuzz=Fuzz -fuzztime 90s ./...

