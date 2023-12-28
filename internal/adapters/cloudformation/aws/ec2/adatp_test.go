package ec2

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-iac/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy-iac/test/testutil"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected ec2.EC2
	}{
		{
			name: "EC2 instance",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      BlockDeviceMappings:
      - DeviceName: "/dev/sdm"
        Ebs:
          VolumeType: "io1"
          Iops: "200"
          DeleteOnTermination: "false"
          VolumeSize: "20"
          Encrypted: "true"`,
			expected: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							HttpEndpoint: types.StringDefault("enabled", types.NewTestMetadata()),
							HttpTokens:   types.StringDefault("optional", types.NewTestMetadata()),
						},
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  types.NewTestMetadata(),
							Encrypted: types.Bool(true, types.NewTestMetadata()),
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
