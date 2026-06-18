// Test-only Go module: the dissector itself is Lua (src/ + dist/). These tests
// drive tshark against the committed pcap fixtures and assert on the decoded
// output; see tests/ and TESTING.md.
module github.com/tarantool/tarantool-dissector

go 1.23

require github.com/stretchr/testify v1.11.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
