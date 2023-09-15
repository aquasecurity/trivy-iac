package google

import (
	"github.com/aquasecurity/defsec/pkg/providers/google"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/bigquery"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/compute"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/dns"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/gke"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/iam"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/kms"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/sql"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/google/storage"
)

func Adapt(modules terraform.Modules) google.Google {
	return google.Google{
		BigQuery: bigquery.Adapt(modules),
		Compute:  compute.Adapt(modules),
		DNS:      dns.Adapt(modules),
		GKE:      gke.Adapt(modules),
		KMS:      kms.Adapt(modules),
		IAM:      iam.Adapt(modules),
		SQL:      sql.Adapt(modules),
		Storage:  storage.Adapt(modules),
	}
}
