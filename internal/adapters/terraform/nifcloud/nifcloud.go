package nifcloud

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/nifcloud/computing"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/nifcloud/dns"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/nifcloud/nas"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/nifcloud/network"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/nifcloud/rdb"
	"github.com/nikpivkin/trivy-iac/internal/adapters/terraform/nifcloud/sslcertificate"
)

func Adapt(modules terraform.Modules) nifcloud.Nifcloud {
	return nifcloud.Nifcloud{
		Computing:      computing.Adapt(modules),
		DNS:            dns.Adapt(modules),
		NAS:            nas.Adapt(modules),
		Network:        network.Adapt(modules),
		RDB:            rdb.Adapt(modules),
		SSLCertificate: sslcertificate.Adapt(modules),
	}
}
