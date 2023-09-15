package config

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/nikpivkin/trivy-iac/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) config.Config {
	return config.Config{
		ConfigurationAggregrator: getConfigurationAggregator(cfFile),
	}
}
