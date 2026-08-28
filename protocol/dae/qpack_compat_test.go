//go:build linux && !android && with_dae

package dae

import (
	"io"
	"testing"

	"github.com/quic-go/qpack"
)

func TestQPACKCompatibilitySurface(t *testing.T) {
	block := []byte{0, 0}

	decode := qpack.NewDecoder().Decode(block)
	if _, err := decode(); err != io.EOF {
		t.Fatalf("modern decoder returned %v", err)
	}

	fields, err := qpack.NewDecoder(func(qpack.HeaderField) {}).DecodeFull(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 0 {
		t.Fatalf("decoded %d unexpected fields", len(fields))
	}
}
