package selfsdk

import (
	"encoding/base64"
)

// Encode encodes a byteslice as url safe base64 byteslice
func Encode(p []byte) []byte {
	enc := base64.RawStdEncoding
	dst := make([]byte, enc.EncodedLen(len(p)))
	enc.Encode(dst, p)
	return dst
}

// EncodeString encodes a base64 url safe encoded string
func EncodeString(p []byte) string {
	return string(Encode(p))
}

// Decode decodes a base64 url encoded string
func Decode(x string) ([]byte, error) {
	enc := base64.RawStdEncoding
	dst := make([]byte, enc.DecodedLen(len([]byte(x))))
	_, err := enc.Decode(dst, []byte(x))
	return dst, err
}

func EncodeURL(src []byte) []byte {
	enc := base64.URLEncoding.WithPadding(base64.NoPadding)
	dst := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(dst, src)
	return dst
}

func DecodeURL(x string) ([]byte, error) {
	enc := base64.URLEncoding.WithPadding(base64.NoPadding)
	dst := make([]byte, enc.DecodedLen(len([]byte(x))))
	_, err := enc.Decode(dst, []byte(x))
	return dst, err
}

func EncodeURLString(src []byte) string {
	return string(EncodeURL([]byte(src)))
}
