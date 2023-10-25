package functions

import (
	"fmt"
	"strconv"
)

func SubString(args ...interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	start, err := getIntValue(args[1])
	if err != nil {
		return ""
	}

	if len(args) == 2 {
		args = append(args, len(input))
	}

	length, err := getIntValue(args[2])
	if err != nil {
		return ""
	}

	if start > len(input) {
		return ""
	}

	if start+length > len(input) {
		return input[start:]
	}

	return input[start : start+length]
}

func getIntValue(value interface{}) (int, error) {
	return strconv.Atoi(fmt.Sprintf("%v", value))
}
