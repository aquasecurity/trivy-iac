package sns

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"
	"github.com/nikpivkin/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) sns.SNS {
	return sns.SNS{
		Topics: getTopics(cfFile),
	}
}
