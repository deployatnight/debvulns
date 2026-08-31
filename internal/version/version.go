// Package version implements Debian (dpkg) version string parsing and
// comparison, mirroring the algorithm used by apt_pkg.version_compare and
// python-debian's NativeVersion.
//
// The comparison is a faithful port of dpkg's lib/dpkg/version.c verrevcmp()
// and order() functions. A Debian version has the form:
//
//	[epoch:]upstream-version[-debian-revision]
//
// Comparison is performed epoch-first, then the upstream version using the
// special "order" algorithm, then the debian revision using the same
// algorithm.
package version

import (
	"errors"
	"strconv"
	"strings"
)

// Version is a parsed Debian version string.
//
// The zero value is not a valid version; construct one with New.
type Version struct {
	raw      string
	epoch    int
	upstream string
	revision string
}

// ErrEmptyVersion is returned by New when the version string is empty.
var ErrEmptyVersion = errors.New("version string cannot be empty")

// New parses a Debian version string.
//
// The epoch is the optional leading integer followed by a colon. The debian
// revision is the optional trailing component after the last hyphen.
func New(s string) (Version, error) {
	if s == "" {
		return Version{}, ErrEmptyVersion
	}

	v := Version{raw: s}

	// Parse epoch: part before the first colon, but only if it is a
	// non-negative integer (mirrors python-debian behaviour).
	if i := strings.IndexByte(s, ':'); i != -1 {
		ep := s[:i]
		if isAllDigits(ep) {
			epoch, err := strconv.Atoi(ep)
			if err != nil {
				return Version{}, err
			}
			v.epoch = epoch
			s = s[i+1:]
		}
	}

	// Split off the debian revision at the LAST hyphen.
	if i := strings.LastIndexByte(s, '-'); i != -1 {
		v.upstream = s[:i]
		v.revision = s[i+1:]
	} else {
		v.upstream = s
	}

	return v, nil
}

// String returns the original version string.
func (v Version) String() string { return v.raw }

// Raw returns the original unparsed version string.
func (v Version) Raw() string { return v.raw }

// Epoch returns the epoch component.
func (v Version) Epoch() int { return v.epoch }

// Upstream returns the upstream-version component.
func (v Version) Upstream() string { return v.upstream }

// Revision returns the debian-revision component.
func (v Version) Revision() string { return v.revision }

// Equal reports whether two versions compare equal.
func (v Version) Equal(o Version) bool { return v.Compare(o) == 0 }

// Less reports whether v is strictly less than o.
func (v Version) Less(o Version) bool { return v.Compare(o) < 0 }

// Greater reports whether v is strictly greater than o.
func (v Version) Greater(o Version) bool { return v.Compare(o) > 0 }

// Compare returns -1, 0 or +1 as v is less than, equal to, or greater than o.
//
// This is a direct port of dpkg's dpkg_version_compare / verrevcmp.
func (v Version) Compare(o Version) int {
	// Compare epochs numerically.
	if v.epoch != o.epoch {
		if v.epoch < o.epoch {
			return -1
		}
		return 1
	}

	if rc := verrevcmp(v.upstream, o.upstream); rc != 0 {
		return rc
	}

	return verrevcmp(v.revision, o.revision)
}

// order returns the dpkg ordering weight of a single byte.
//
//   - NUL and digits weigh 0 (digits are handled by the numeric phase, and NUL
//     acts as the terminator).
//   - '~' weighs -1 (sorts before everything, including end-of-string).
//   - ASCII letters weigh their own value.
//   - Other non-NUL bytes weigh value+256 (so they sort after letters).
func order(c byte) int {
	switch {
	case c == 0:
		return 0
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp is a port of dpkg's verrevcmp(): it compares two version
// components by alternating between an alphabetic phase (using order()) and a
// numeric phase (comparing digit runs as integers).
func verrevcmp(a, b string) int {
	ia, ib := 0, 0
	la, lb := len(a), len(b)

	for ia < la || ib < lb {
		var firstDiff int

		// Alphabetic phase: advance while either side has a non-digit byte.
		for (ia < la && !isDigit(a[ia])) || (ib < lb && !isDigit(b[ib])) {
			ac, bc := 0, 0
			if ia < la {
				ac = order(a[ia])
			}
			if ib < lb {
				bc = order(b[ib])
			}
			if ac != bc {
				return ac - bc
			}
			if ia < la {
				ia++
			}
			if ib < lb {
				ib++
			}
		}

		// Numeric phase: strip leading zeros, then compare digit runs.
		for ia < la && a[ia] == '0' {
			ia++
		}
		for ib < lb && b[ib] == '0' {
			ib++
		}

		for ia < la && ib < lb && isDigit(a[ia]) && isDigit(b[ib]) {
			if firstDiff == 0 {
				firstDiff = int(a[ia]) - int(b[ib])
			}
			ia++
			ib++
		}

		switch {
		case ia < la && isDigit(a[ia]):
			// a has more digits -> larger number.
			return 1
		case ib < lb && isDigit(b[ib]):
			// b has more digits -> larger number.
			return -1
		case firstDiff != 0:
			return firstDiff
		}
	}

	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// MustNew is like New but panics on error. Intended for tests/constants.
func MustNew(s string) Version {
	v, err := New(s)
	if err != nil {
		panic(err)
	}
	return v
}
