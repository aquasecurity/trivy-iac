package parser

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParameters_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected Parameters
	}{
		{
			name: "original format",
			source: `[
				"Key1=Value1",
				"Key2=Value2"
			]`,
			expected: map[string]any{
				"Key1": "Value1",
				"Key2": "Value2",
			},
		},
		{
			name: "CloudFormation like format",
			source: `[
				{
					 "ParameterKey": "Key1",
					 "ParameterValue": "Value1"
				 },
				 {
					 "ParameterKey": "Key2",
					 "ParameterValue": "Value2"
				 }
			 ]`,
			expected: map[string]any{
				"Key1": "Value1",
				"Key2": "Value2",
			},
		},
		{
			name: "CodePipeline like format",
			source: `{
				"Parameters": {
					"Key1": "Value1",
					"Key2": "Value2"
				}
			}`,
			expected: map[string]any{
				"Key1": "Value1",
				"Key2": "Value2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params Parameters
			require.NoError(t, json.Unmarshal([]byte(tt.source), &params))

			assert.Equal(t, tt.expected, params)
		})
	}
}
