package identity

import (
	"errors"
	"math/big"
)

// Base58btc alphabet (Bitcoin).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	// Preserve leading zeros.
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	// Reverse.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func base58Decode(s string) ([]byte, error) {
	x := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range []byte(s) {
		idx := indexOf(base58Alphabet, c)
		if idx < 0 {
			return nil, errors.New("invalid base58 character")
		}
		x.Mul(x, base)
		x.Add(x, big.NewInt(int64(idx)))
	}

	result := x.Bytes()

	// Restore leading zeros.
	for _, c := range []byte(s) {
		if c != base58Alphabet[0] {
			break
		}
		result = append([]byte{0}, result...)
	}

	return result, nil
}

func indexOf(alphabet string, c byte) int {
	for i := range len(alphabet) {
		if alphabet[i] == c {
			return i
		}
	}
	return -1
}
