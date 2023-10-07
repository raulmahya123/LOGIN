package helpers

import (
	"github.com/o1egl/paseto"
)

var (
	// Ganti dengan kunci rahasia Anda
	secretKey = []byte("your_secret_key_here")
)

// Claims adalah struktur untuk menampung klaim token
type Claims struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Uid       string `json:"uid"`
	UserType  string `json:"user_type"`
}

// NewV2Public adalah metode publik untuk membuat instance PASETO V2.
func NewV2Public() *paseto.V2 {
	return paseto.NewV2()
}

// GenerateToken menghasilkan token PASETO dari claim yang diberikan.
func GenerateToken(claims Claims) (string, error) {
	v2 := NewV2Public()

	// Buat token PASETO
	token, err := v2.Encrypt(secretKey, claims, nil)
	if err != nil {
		return "", err
	}

	// Kembalikan token dalam bentuk JSON Web Token (JWT)
	return token, nil
}

// VerifyToken memverifikasi token PASETO dan mengembalikan claims jika valid.
func VerifyTokenn(token string) (Claims, error) {
	var claims Claims

	// Buat dekoder PASETO
	v2 := NewV2Public()

	// Verifikasi token
	err := v2.Decrypt(token, secretKey, &claims, nil)
	if err != nil {
		return Claims{}, err
	}

	return claims, nil
}
