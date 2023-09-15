package neptune

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/neptune"
	"github.com/nikpivkin/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) neptune.Neptune {
	return neptune.Neptune{
		Clusters: getClusters(cfFile),
	}
}
