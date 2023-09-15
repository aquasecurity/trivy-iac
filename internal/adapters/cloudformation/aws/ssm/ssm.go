package ssm

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ssm"
	"github.com/nikpivkin/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) ssm.SSM {
	return ssm.SSM{
		Secrets: getSecrets(cfFile),
	}
}
