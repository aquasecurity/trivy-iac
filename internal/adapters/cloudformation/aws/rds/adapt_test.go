package rds

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-iac/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy-iac/test/testutil"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected rds.RDS
	}{
		{
			name: "cluster with instances",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  RDSCluster:
    Type: 'AWS::RDS::DBCluster'
    Properties:
      DBClusterIdentifier: my-cluster1
      Engine: aurora-postgresql
      StorageEncrypted: true
      KmsKeyId: "your-kms-key-id"
  RDSDBInstance1:
    Type: 'AWS::RDS::DBInstance'
    Properties:
      Engine: aurora-mysql
      DBInstanceIdentifier: test
      DBClusterIdentifier:
        Ref: RDSCluster
      PubliclyAccessible: 'true'
      DBInstanceClass: db.r3.xlarge
`,
			expected: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata:                  types.NewTestMetadata(),
						BackupRetentionPeriodDays: types.IntDefault(1, types.NewTestMetadata()),
						Engine:                    types.String("aurora-postgresql", types.NewTestMetadata()),
						Encryption: rds.Encryption{
							EncryptStorage: types.Bool(true, types.NewTestMetadata()),
							KMSKeyID:       types.String("your-kms-key-id", types.NewTestMetadata()),
						},
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									Metadata:                  types.NewTestMetadata(),
									DBInstanceIdentifier:      types.String("test", types.NewTestMetadata()),
									PubliclyAccessible:        types.Bool(true, types.NewTestMetadata()),
									PublicAccess:              types.BoolDefault(true, types.NewTestMetadata()),
									BackupRetentionPeriodDays: types.IntDefault(1, types.NewTestMetadata()),
									Engine:                    types.StringDefault("aurora-mysql", types.NewTestMetadata()),
								},
								ClusterIdentifier: types.String("RDSCluster", types.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := testutil.CreateFS(t, map[string]string{
				"template.yaml": tt.source,
			})

			p := parser.New()
			fctx, err := p.ParseFile(context.TODO(), fs, "template.yaml")
			require.NoError(t, err)

			testutil.AssertDefsecEqual(t, tt.expected, Adapt(*fctx))
		})
	}

}
