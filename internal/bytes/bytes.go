// Package bytes contains byte-slice helpers shared by internal implementations.
package bytes

// LeftPad returns b unchanged when it already has at least size bytes;
// otherwise it returns a zero-padded copy of exactly size bytes.
func LeftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
