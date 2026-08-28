package qpack

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestModernAndLegacyDecoderAPIs(t *testing.T) {
	input := []HeaderField{{Name: ":method", Value: "GET"}, {Name: "x-test", Value: "value"}}
	var encoded bytes.Buffer
	encoder := NewEncoder(&encoded)
	for _, field := range input {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}

	modern := NewDecoder().Decode(encoded.Bytes())
	var modernFields []HeaderField
	for {
		field, err := modern()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		modernFields = append(modernFields, field)
	}
	if !reflect.DeepEqual(modernFields, input) {
		t.Fatalf("modern fields = %#v", modernFields)
	}

	legacyFields, err := NewDecoder(func(HeaderField) {}).DecodeFull(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacyFields, input) {
		t.Fatalf("legacy fields = %#v", legacyFields)
	}

	var callbackFields []HeaderField
	decoder := NewDecoder(func(field HeaderField) { callbackFields = append(callbackFields, field) })
	if _, err = decoder.Write(encoded.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(callbackFields, input) {
		t.Fatalf("callback fields = %#v", callbackFields)
	}
}
