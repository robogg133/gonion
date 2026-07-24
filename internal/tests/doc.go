// Package tests holds live integration tests against the Tor network.
//
// Unit tests live next to the code they cover:
//
//	gonion/*_test.go
//	internal/hops/*_test.go
//	internal/window/*_test.go
//	internal/shared/*_test.go
//	pkg/cells/.../*_test.go
//	pkg/crypto/*_test.go
//	pkg/lspec/*_test.go
//	pkg/common/*_test.go
//
// Run only unit tests (no network):
//
//	go test ./... -short
//
// Run integration tests:
//
//	go test ./internal/tests/ -count=1 -timeout 10m
package tests
