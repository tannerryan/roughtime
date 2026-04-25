package constanttime

import "crypto/subtle"

// Select returns x if v == 1 and y if v == 0.
// Its behavior is undefined if v takes any other value.
func Select(v, x, y int) int {
	return subtle.ConstantTimeSelect(v, x, y)
}

// ByteEq returns 1 if x == y and 0 otherwise.
func ByteEq(x, y uint8) int {
	return subtle.ConstantTimeByteEq(x, y)
}

// Eq returns 1 if x == y and 0 otherwise.
func Eq(x, y int32) int {
	return subtle.ConstantTimeEq(x, y)
}

// LessOrEq returns 1 if x <= y and 0 otherwise.
// Its behavior is undefined if x or y are negative or > 2**31 - 1.
func LessOrEq(x, y int) int {
	return subtle.ConstantTimeLessOrEq(x, y)
}
