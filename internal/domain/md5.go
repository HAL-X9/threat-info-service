package domain

import "strings"

// md5Length is the length of an MD5 digest written as hexadecimal.
const md5Length = 32

// MD5 is the identifier of a threat: the MD5 hash of the malicious file,
// as 32 lowercase hexadecimal characters. Obtain one with ParseMD5.
type MD5 string

// ParseMD5 validates s and returns it in lowercase, so that the same hash
// written in any case identifies the same threat.
func ParseMD5(s string) (MD5, error) {
	if len(s) != md5Length {
		return "", invalidMD5()
	}

	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return "", invalidMD5()
		}
	}

	return MD5(strings.ToLower(s)), nil
}

func (m MD5) String() string { return string(m) }

func invalidMD5() error {
	return invalid("md5 must be %d hexadecimal characters", md5Length)
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
