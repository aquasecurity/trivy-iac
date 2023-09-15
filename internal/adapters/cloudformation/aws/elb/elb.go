package elb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/nikpivkin/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) elb.ELB {
	return elb.ELB{
		LoadBalancers: getLoadBalancers(cfFile),
	}
}
