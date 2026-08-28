package qpack

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2/hpack"
)

type invalidIndexError int

func (e invalidIndexError) Error() string {
	return fmt.Sprintf("invalid indexed representation index %d", int(e))
}

var errNoDynamicTable = errors.New("no dynamic table")

// Decoder implements qpack v0.6's iterator API and the v0.5 callback API.
// The compatibility surface is deliberately limited to NewDecoder's optional
// callback and DecodeFull. Both use the same v0.6 parser.
type Decoder struct {
	emitFunc func(HeaderField)
}

type DecodeFunc func() (HeaderField, error)

// NewDecoder accepts zero arguments (qpack v0.6) or one callback (v0.5).
func NewDecoder(emitFunc ...func(HeaderField)) *Decoder {
	decoder := &Decoder{}
	if len(emitFunc) > 1 {
		panic("qpack: NewDecoder accepts at most one callback")
	}
	if len(emitFunc) == 1 {
		decoder.emitFunc = emitFunc[0]
	}
	return decoder
}

// Decode returns an iterator over the supplied header block.
func (d *Decoder) Decode(p []byte) DecodeFunc {
	var readRequiredInsertCount bool
	var readDeltaBase bool
	return func() (HeaderField, error) {
		if !readRequiredInsertCount {
			requiredInsertCount, rest, err := readVarInt(8, p)
			if err != nil {
				return HeaderField{}, err
			}
			p = rest
			readRequiredInsertCount = true
			if requiredInsertCount != 0 {
				return HeaderField{}, errors.New("expected Required Insert Count to be zero")
			}
		}
		if !readDeltaBase {
			base, rest, err := readVarInt(7, p)
			if err != nil {
				return HeaderField{}, err
			}
			p = rest
			readDeltaBase = true
			if base != 0 {
				return HeaderField{}, errors.New("expected Base to be zero")
			}
		}
		if len(p) == 0 {
			return HeaderField{}, io.EOF
		}
		b := p[0]
		var hf HeaderField
		var rest []byte
		var err error
		switch {
		case b&0x80 > 0:
			hf, rest, err = d.parseIndexedHeaderField(p)
		case b&0xc0 == 0x40:
			hf, rest, err = d.parseLiteralHeaderField(p)
		case b&0xe0 == 0x20:
			hf, rest, err = d.parseLiteralHeaderFieldWithoutNameReference(p)
		default:
			err = fmt.Errorf("unexpected type byte: %#x", b)
		}
		p = rest
		if err != nil {
			return HeaderField{}, err
		}
		return hf, nil
	}
}

// DecodeFull restores qpack v0.5's whole-block API without changing v0.6
// iterator behavior. Like v0.5, the constructor callback is not invoked by
// DecodeFull; callers receive the returned slice.
func (d *Decoder) DecodeFull(p []byte) ([]HeaderField, error) {
	decode := d.Decode(p)
	fields := make([]HeaderField, 0, 8)
	for {
		field, err := decode()
		if errors.Is(err, io.EOF) {
			return fields, nil
		}
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
}

// Write restores the v0.5 io.Writer entry point for consumers that still use
// callback-based full blocks. Incremental partial blocks are intentionally not
// supported: callers must pass one complete header block per Write call.
func (d *Decoder) Write(p []byte) (int, error) {
	fields, err := d.DecodeFull(p)
	if err != nil {
		return 0, err
	}
	if d.emitFunc != nil {
		for _, field := range fields {
			d.emitFunc(field)
		}
	}
	return len(p), nil
}

// Close is retained for qpack v0.5 source compatibility. Decoder state is
// block-local in v0.6, so there is nothing to reset.
func (d *Decoder) Close() error { return nil }

func (d *Decoder) parseIndexedHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
	if buf[0]&0x40 == 0 {
		return HeaderField{}, buf, errNoDynamicTable
	}
	index, rest, err := readVarInt(6, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.at(index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	return hf, rest, nil
}

func (d *Decoder) parseLiteralHeaderField(buf []byte) (_ HeaderField, rest []byte, _ error) {
	if buf[0]&0x10 == 0 {
		return HeaderField{}, buf, errNoDynamicTable
	}
	index, rest, err := readVarInt(4, buf)
	if err != nil {
		return HeaderField{}, buf, err
	}
	hf, ok := d.at(index)
	if !ok {
		return HeaderField{}, buf, invalidIndexError(index)
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, buf, io.ErrUnexpectedEOF
	}
	usesHuffman := buf[0]&0x80 > 0
	val, rest, err := d.readString(rest, 7, usesHuffman)
	if err != nil {
		return HeaderField{}, rest, err
	}
	hf.Value = val
	return hf, rest, nil
}

func (d *Decoder) parseLiteralHeaderFieldWithoutNameReference(buf []byte) (_ HeaderField, rest []byte, _ error) {
	usesHuffmanForName := buf[0]&0x8 > 0
	name, rest, err := d.readString(buf, 3, usesHuffmanForName)
	if err != nil {
		return HeaderField{}, rest, err
	}
	buf = rest
	if len(buf) == 0 {
		return HeaderField{}, rest, io.ErrUnexpectedEOF
	}
	usesHuffmanForVal := buf[0]&0x80 > 0
	val, rest, err := d.readString(buf, 7, usesHuffmanForVal)
	if err != nil {
		return HeaderField{}, rest, err
	}
	return HeaderField{Name: name, Value: val}, rest, nil
}

func (d *Decoder) readString(buf []byte, n uint8, usesHuffman bool) (string, []byte, error) {
	l, buf, err := readVarInt(n, buf)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(buf)) < l {
		return "", nil, io.ErrUnexpectedEOF
	}
	var val string
	if usesHuffman {
		val, err = hpack.HuffmanDecodeToString(buf[:l])
		if err != nil {
			return "", nil, err
		}
	} else {
		val = string(buf[:l])
	}
	return val, buf[l:], nil
}

func (d *Decoder) at(i uint64) (HeaderField, bool) {
	if i >= uint64(len(staticTableEntries)) {
		return HeaderField{}, false
	}
	return staticTableEntries[i], true
}
