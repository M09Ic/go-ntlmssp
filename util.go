package ntlmssp

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"reflect"
	"strings"
	"unicode/utf16"
	"unsafe"
)

func displayBits(offset int, set bool) string {
	buf := strings.Builder{}
	for i := 0; i < 8; i++ {
		for j := 0; j < 4; j++ {
			if offset == i*4+j {
				if set {
					buf.Write([]byte{'1'})
				} else {
					buf.Write([]byte{'0'})
				}
			} else {
				buf.Write([]byte{'.'})
			}
		}
		buf.Write([]byte{' '})
	}
	return buf.String()
}

func bytes2Uint(bs []byte, endian byte) uint64 {
	var u uint64
	if endian == '>' {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[i]) << uint(8*(len(bs)-i-1))
		}
	} else {
		for i := 0; i < len(bs); i++ {
			u += uint64(bs[len(bs)-i-1]) << uint(8*(len(bs)-i-1))
		}
	}
	return u
}

// Only for ascii
func encodeUTF16LE(bs []byte) []byte {
	output := make([]byte, 0, len(bs)*2)
	for i := 0; i < len(bs); i++ {
		output = append(output, bs[i])
		output = append(output, 0)
	}
	return output
}

// UTF16 multi bytes to string
func bytes2StringUTF16(bs []byte) string {
	ptr := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	(*ptr).Len = ptr.Len / 2

	s := (*[]uint16)(unsafe.Pointer(&bs))
	return string(utf16.Decode(*s))
}

func padding(bs []byte) []byte {
	output := make([]byte, 0, 8)
	output = append(output, 1+(bs[0]>>1)<<1)
	output = append(output, 1+((bs[0]&1)<<7)+((bs[1]&0xfc)>>1))
	output = append(output, 1+((bs[1]&0x3)<<6)+((bs[2]&0xf8)>>2))
	output = append(output, 1+((bs[2]&0x7)<<5)+((bs[3]&0xf0)>>3))
	output = append(output, 1+((bs[3]&0xf)<<4)+((bs[4]&0xe0)>>4))
	output = append(output, 1+((bs[4]&0x1f)<<3)+((bs[5]&0xc0)>>5))
	output = append(output, 1+((bs[5]&0x3f)<<2)+((bs[6]&0x80)>>6))
	output = append(output, 1+(bs[6]&0x7f)<<1)
	return output
}

func desEnc(key []byte, plaintext []byte) []byte {
	cipher := make([]byte, 8)
	c, _ := des.NewCipher(key)
	c.Encrypt(cipher, plaintext)
	return cipher
}

func hmacMd5(key []byte, msg []byte) []byte {
	hsh := hmac.New(md5.New, key)
	hsh.Write(msg)
	return hsh.Sum(nil)
}

func md5Hash(msg []byte) []byte {
	hsh := md5.New()
	hsh.Write(msg)
	return hsh.Sum(nil)
}
