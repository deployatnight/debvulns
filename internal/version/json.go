package version

import "encoding/json"

// MarshalJSON renders a Version as its raw string, so cached data is
// human-readable and compatible with the Python debvulns cache format.
func (v Version) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.raw)
}

// UnmarshalJSON parses a Version from a JSON string. An empty/NULL value
// yields the zero Version (not a valid version; callers must check).
func (v *Version) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*v = Version{}
		return nil
	}
	parsed, err := New(s)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}
