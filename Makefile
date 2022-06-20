build:
	go build

test:
	go test -race -v ./...

install_lint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.41.1

lint:
	golangci-lint --version
	golangci-lint run -E gofmt -E gosec -E goconst -E gocritic --timeout=5m
#   golangci-lint run -E stylecheck -E gosec -E goconst -E godox -E gocritic

fmt:
	gofmt -s -w .

deps_update:
	go get -u ./...


export_actors_cid:
	go run ./actors/gen
