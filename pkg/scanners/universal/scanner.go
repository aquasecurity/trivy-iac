package universal

import (
	"context"
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/azure/arm"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/cloudformation"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/dockerfile"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/helm"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/json"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/kubernetes"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/terraform"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/toml"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/yaml"
)

type nestableFSScanners interface {
	scanners.FSScanner
	options.ConfigurableScanner
}

var _ scanners.FSScanner = (*Scanner)(nil)

type Scanner struct {
	fsScanners []nestableFSScanners
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		fsScanners: []nestableFSScanners{
			terraform.New(opts...),
			cloudformation.New(opts...),
			dockerfile.NewScanner(opts...),
			kubernetes.NewScanner(opts...),
			json.NewScanner(opts...),
			yaml.NewScanner(opts...),
			toml.NewScanner(opts...),
			helm.New(opts...),
			arm.New(opts...),
		},
	}
	return s
}

func (s *Scanner) Name() string {
	return "Universal"
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	for _, inner := range s.fsScanners {
		innerResults, err := inner.ScanFS(ctx, fs, dir)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}
