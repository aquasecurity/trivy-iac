package functions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_UniqueString(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected string
	}{
		{
			name: "unique string from a string",
			args: []interface{}{
				"hello",
			},
			expected: "htpi75jfihg4e",
		},
		{
			name: "unique string from a string",
			args: []interface{}{
				"world",
			},
			expected: "iw4p5eg6q6hta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := UniqueString(tt.args...)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
