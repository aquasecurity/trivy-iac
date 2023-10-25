package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/trivy-iac/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy-iac/test/testutil"
)

func Test_adaptRoles(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []iam.Role
	}{
		{
			name: "policy",
			terraform: `
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id

  policy = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "s3.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy_document" "policy" {
	version = "2012-10-17"
	statement {
	  effect    = "Allow"
	  actions   = ["ec2:Describe*"]
	  resources = ["*"]
	}
  }
`,
			expected: []iam.Role{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("test_role", defsecTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("test_policy", defsecTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "policy attachment",
			terraform: `
resource "aws_iam_role" "role" {
  name               = "test-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "aws_iam_policy_document" "policy" {
  version = "2012-10-17"
  statement {
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"
  policy      = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}
`,
			expected: []iam.Role{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("test-role", defsecTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("test-policy", defsecTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(true),
						},
					},
				},
			},
		},
		{
			name: "inline policy",
			terraform: `
resource "aws_iam_role" "example" {
  name               = "test-role"
  
  inline_policy {
    name = "my_inline_policy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["ec2:Describe*"]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
}
`,
			expected: []iam.Role{
				{
					Metadata: defsecTypes.NewTestMetadata(),
					Name:     defsecTypes.String("test-role", defsecTypes.NewTestMetadata()),
					Policies: []iam.Policy{
						{
							Metadata: defsecTypes.NewTestMetadata(),
							Name:     defsecTypes.String("my_inline_policy", defsecTypes.NewTestMetadata()),
							Document: defaultPolicyDocuemnt(false),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRoles(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
