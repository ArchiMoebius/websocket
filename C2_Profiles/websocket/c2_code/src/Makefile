export GO111MODULE=on

VERSION=$(shell date '+%Y%m%d')
BUILD=$(shell git rev-parse HEAD)
BASEDIR=./dist
DIR=${BASEDIR}/

LDFLAGS=-ldflags "-s -w -X main.build=${BUILD} -X github.com:ArchiMoebius/mythic_c2_websocket/pkg.BuildVersion=${VERSION} -buildid=${BUILD}"
GCFLAGS=-gcflags=all=-trimpath=$(shell echo ${HOME})
ASMFLAGS=-asmflags=all=-trimpath=$(shell echo ${HOME})

GOFILES=`go list ./...`
GOFILESNOTEST=`go list ./... | grep -v test`

all: lint linux

linux: lint
	env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ./server ./cmd/server/main.go

tidy:
	@go mod tidy

dep: tidy ## Get the dependencies
	@go get -v -d ./...
	@go get -u all

lint: ## Lint the files
	@go fmt ${GOFILES}
	@go vet ${GOFILESNOTEST}

clean:
	rm -f server

.PHONY: all linux tidy dep lint clean
