.PHONY: test
test:
	go test -race ./...

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.54.2
	golangci-lint run --timeout 3m --verbose

.PHONY: update-aws-deps
update-aws-deps:
	@grep aws-sdk-go-v2 go.mod | grep -v '// indirect' | sed 's/^[\t\s]*//g' | sed 's/\s.*//g' | xargs go get
	@go mod tidy

.PHONY: schema
schema:
	go run ./cmd/schema generate

.PHONY: docs
docs:
	go run ./cmd/avd_generator

.PHONY: docs-test
docs-test:
	go test -v ./cmd/avd_generator/...
