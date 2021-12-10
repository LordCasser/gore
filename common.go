package gore

import (
	"math/rand"
	"unicode"
)

func GetRandomString(n int) string {
	str := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes := []byte(str)
	var result []byte
	for i := 0; i < n; i++ {
		result = append(result, bytes[rand.Intn(len(bytes))])
	}
	return string(result)
}

func IsASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

type TypeData struct {
	Offset uint64
	Length uint64
}
type TypeStringOffset struct {
	Base    uint64
	PCLnTab uint64
	Datas   []TypeData
}

var TypeStringOffsets = new(TypeStringOffset)
