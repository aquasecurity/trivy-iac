package digitalocean

import (
	"github.com/aquasecurity/defsec/pkg/providers/digitalocean"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/wuwwlwwl/trivy-iac/internal/adapters/terraform/digitalocean/compute"
	"github.com/wuwwlwwl/trivy-iac/internal/adapters/terraform/digitalocean/spaces"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}
