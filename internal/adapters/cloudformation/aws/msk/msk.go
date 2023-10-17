package msk

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/msk"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) msk.MSK {
	return msk.MSK{
		Clusters: getClusters(cfFile),
	}
}
