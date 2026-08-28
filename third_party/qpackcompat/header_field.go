package qpack

// A HeaderField is a name-value pair. Both the name and value are
// treated as opaque sequences of octets.
type HeaderField struct {
	Name  string
	Value string
}

// IsPseudo reports whether the header field is an HTTP3 pseudo header.
func (hf HeaderField) IsPseudo() bool {
	return len(hf.Name) != 0 && hf.Name[0] == ':'
}
