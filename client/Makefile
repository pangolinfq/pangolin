all: windows linux darwin

.PHONY: all clean

windows:
	GOOS=windows GOARCH=386 go build -ldflags "-H windowsgui" -o pangolin.exe

linux:
	GOOS=linux GOARCH=amd64 go build -o pangolin

darwin:
	GOOS=darwin GOARCH=amd64 go build -o pangolin_mac

clean:
	rm pangolin pangolin.exe pangolin_mac
