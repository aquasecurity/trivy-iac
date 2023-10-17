package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/wuwwlwwl/trivy-iac/internal/adapters/cloudformation/aws"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
