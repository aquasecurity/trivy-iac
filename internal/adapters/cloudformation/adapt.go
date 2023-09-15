package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/nikpivkin/trivy-iac/internal/adapters/cloudformation/aws"
	"github.com/nikpivkin/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
