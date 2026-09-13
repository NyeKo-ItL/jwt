// Package option contains small helpers shared by public constructors.
package option

// FirstString returns the first optional string, or the empty string.
func FirstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
