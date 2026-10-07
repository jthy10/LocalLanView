// Package auth handles the console password, sessions, CSRF tokens and
// login throttling.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (OWASP-recommended baseline).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns a PHC-style argon2id string.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("auth: unrecognized password hash")

// VerifyPassword checks pw against an encoded hash in constant time.
func VerifyPassword(pw, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// GeneratePassword returns a random password that's easy to type: no
// ambiguous characters, grouped in fours.
func GeneratePassword() (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		// 256 % 54 bias is negligible for this purpose, but avoid it anyway.
		for int(v) >= 256-256%len(alphabet) {
			var one [1]byte
			rand.Read(one[:])
			v = one[0]
		}
		sb.WriteByte(alphabet[int(v)%len(alphabet)])
	}
	return sb.String(), nil
}

var common = map[string]bool{
	"password": true, "password1": true, "password123": true, "123456789012": true,
	"qwertyuiop": true, "letmein": true, "administrator": true, "changeme": true,
	"locallanview": true, "admin": true, "welcome": true, "iloveyou": true,
}

// CheckStrength explains why a password is too weak, or returns nil. This is
// what "strong" means for exposing the console beyond loopback.
func CheckStrength(pw, user string) error {
	if len([]rune(pw)) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	lower := strings.ToLower(pw)
	if common[lower] || strings.Contains(lower, "password") {
		return errors.New("password is too common")
	}
	if user != "" && strings.Contains(lower, strings.ToLower(user)) {
		return errors.New("password must not contain the username")
	}
	var classes [4]bool
	uniq := map[rune]bool{}
	for _, r := range pw {
		uniq[r] = true
		switch {
		case unicode.IsLower(r):
			classes[0] = true
		case unicode.IsUpper(r):
			classes[1] = true
		case unicode.IsDigit(r):
			classes[2] = true
		default:
			classes[3] = true
		}
	}
	n := 0
	for _, c := range classes {
		if c {
			n++
		}
	}
	if len(uniq) < 6 {
		return errors.New("password has too few distinct characters")
	}
	if n < 3 && len([]rune(pw)) < 16 {
		return errors.New("use at least 16 characters, or mix 3 of: lowercase, uppercase, digits, symbols")
	}
	return nil
}
