package azure

import (
	"testing"
	"time"

	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/stretchr/testify/require"
)

func Test_resolveFunc(t *testing.T) {

	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "simple format call",
			expr:     "format('{0}/{1}', 'myPostgreSQLServer', 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
		{
			name:     "simple format call with numbers",
			expr:     "format('{0} + {1} = {2}', 1, 2, 3)",
			expected: "1 + 2 = 3",
		},
		{
			name:     "format with nested format",
			expr:     "format('{0} + {1} = {2}', format('{0}', 1), 2, 3)",
			expected: "1 + 2 = 3",
		},
		{
			name:     "format with multiple nested format",
			expr:     "format('{0} + {1} = {2}', format('{0}', 1), 2, format('{0}', 3))",
			expected: "1 + 2 = 3",
		},
		{
			name:     "format with nested base64",
			expr:     "format('the base64 of \"hello, world\" is {0}', base64('hello, world'))",
			expected: "the base64 of \"hello, world\" is aGVsbG8sIHdvcmxk",
		},
		{
			name:     "dateTimeAdd with add a day",
			expr:     "dateTimeAdd(utcNow('yyyy-MM-dd'), 'P1D', 'yyyy-MM-dd')",
			expected: time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02"),
		},
		{
			name:     "simple concat call",
			expr:     "concat('myPostgreSQLServer', '/', 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := resolver{}

			resolvedValue, err := resolver.resolveExpressionString(tt.expr, types.NewTestMetadata())
			require.NoError(t, err)
			require.Equal(t, KindString, resolvedValue.Kind)

			require.Equal(t, tt.expected, resolvedValue.AsString())
		})
	}
}

func Test_resolveParameter(t *testing.T) {
	tests := []struct {
		name       string
		deployment *Deployment
		expr       string
		expected   string
	}{

		{
			name: "format call with parameter1",
			deployment: &Deployment{
				Parameters: []Parameter{
					{
						Variable: Variable{
							Name:  "dbName",
							Value: NewValue("myPostgreSQLServer", types.NewTestMetadata()),
						},
					},
				},
			},
			expr:     "format('{0}/{1}', parameters('dbName'), 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
		{
			name: "format call with parameter2",
			deployment: &Deployment{
				Parameters: []Parameter{
					{
						Variable: Variable{
							Name:  "test",
							Value: NewValue(map[string]interface{}{"dbName": "myPostgreSQLServer"}, types.NewTestMetadata()),
						},
					},
				},
			},
			expr:     "format('{0}/{1}', parameters('test').dbName, 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
		{
			name: "format call with parameter3",
			deployment: &Deployment{
				Parameters: []Parameter{
					{
						Variable: Variable{
							Name:  "test",
							Value: NewValue([]interface{}{map[string]interface{}{"dbName": "myPostgreSQLServer"}}, types.NewTestMetadata()),
						},
					},
				},
			},
			expr:     "format('{0}/{1}', parameters('test')[0].dbName, 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
		{
			name: "format call with parameter4",
			deployment: &Deployment{
				Parameters: []Parameter{
					{
						Variable: Variable{
							Name:  "test",
							Value: NewValue([]interface{}{map[string]interface{}{"dbName": []interface{}{"myPostgreSQLServer"}}}, types.NewTestMetadata()),
						},
					},
				},
			},
			expr:     "format('{0}/{1}', parameters('test')[0].dbName[0], 'log_checkpoints')",
			expected: "myPostgreSQLServer/log_checkpoints",
		},
		{
			name: "format call with parameter5",
			deployment: &Deployment{
				Parameters: []Parameter{
					{
						Variable: Variable{
							Name:  "test",
							Value: NewValue([]interface{}{map[string]interface{}{"dbName": []interface{}{"myPostgreSQLServer"}, "count": "2"}}, types.NewTestMetadata()),
						},
					},
				},
			},
			expr:     "parameters('test')[0].count",
			expected: "2",
		},
		{
			name: "format call with variables1",
			deployment: &Deployment{
				Variables: []Variable{
					{
						Name:  "test",
						Value: NewValue([]interface{}{"test1", "test2"}, types.NewTestMetadata()),
					},
				},
			},
			expr:     "uniqueString(variables('test')[0]))",
			expected: "7465737431e3b",
		},
		{
			name: "format call with variables2",
			deployment: &Deployment{
				Parameters: []Parameter{
					{
						Variable: Variable{
							Name:  "test",
							Value: NewValue([]interface{}{map[string]interface{}{"dbName": []interface{}{"myPostgreSQLServer"}}}, types.NewTestMetadata()),
						},
					},
				},
				Variables: []Variable{
					{
						Name:  "test",
						Value: NewValue([]interface{}{"[parameters('test')[0].dbName[0]]", "test2"}, types.NewTestMetadata()),
					},
				},
			},
			expr:     "variables('test')[0])",
			expected: "myPostgreSQLServer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := resolver{
				deployment: tt.deployment,
			}

			resolvedValue, err := resolver.resolveExpressionString(tt.expr, types.NewTestMetadata())
			require.NoError(t, err)
			require.Equal(t, KindString, resolvedValue.Kind)

			require.Equal(t, tt.expected, resolvedValue.AsString())
		})
	}

}

func Test_resolver(t *testing.T) {
	tests := []struct {
		name       string
		deployment *Deployment
		expr       string
		expected   string
	}{

		{
			name:       "substring call ",
			deployment: &Deployment{},
			expr:       "substring('2f73756273637',0, 3)",
			expected:   "2f7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := resolver{
				deployment: tt.deployment,
			}

			resolvedValue, err := resolver.resolveExpressionString(tt.expr, types.NewTestMetadata())
			require.NoError(t, err)
			require.Equal(t, KindString, resolvedValue.Kind)

			require.Equal(t, tt.expected, resolvedValue.AsString())
		})
	}

}
