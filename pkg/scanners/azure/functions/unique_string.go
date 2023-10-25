package functions

import (
	uniquestring "github.com/wuwwlwwl/go-unique-string"
)

func UniqueString(args ...interface{}) interface{} {
	if len(args) != 1 {
		return ""
	}

	str, ok := args[0].(string)
	if !ok {
		return ""
	}

	return uniquestring.GenerateUniqueString(str)
}
