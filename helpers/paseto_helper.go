package helpers

import (
	"github.com/o1egl/paseto"
)

// VerifyToken digunakan untuk memverifikasi token PASETO
func VerifyToken(token string) (Claims, error) {
	var claims Claims

	// Buat dekoder PASETO
	v2 := paseto.NewV2()

	// Verifikasi token
	err := v2.Decrypt(token, secretKey, &claims, nil)
	if err != nil {
		return Claims{}, err
	}

	return claims, nil
}
