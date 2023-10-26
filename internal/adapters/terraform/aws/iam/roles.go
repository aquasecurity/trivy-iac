package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func adaptRoles(modules terraform.Modules) []iam.Role {

	var output []iam.Role

	for roleBlockID, role := range mapRoles(modules) {
		if policy, ok := applyForDependentResource(
			modules, roleBlockID, "name", "aws_iam_role_policy", "role", findPolicy(modules),
		); ok && policy != nil {
			role.Policies = append(role.Policies, *policy)
		}

		if policy, ok := applyForDependentResource(
			modules, roleBlockID, "name", "aws_iam_role_policy_attachment", "role", findAttachmentPolicy(modules),
		); ok && policy != nil {
			role.Policies = append(role.Policies, *policy)
		}
		output = append(output, role)
	}
	return output
}

func mapRoles(modules terraform.Modules) map[string]iam.Role {
	roleMap := make(map[string]iam.Role)
	for _, roleBlock := range modules.GetResourcesByType("aws_iam_role") {
		role := iam.Role{
			Metadata: roleBlock.GetMetadata(),
			Name:     roleBlock.GetAttribute("name").AsStringValueOrDefault("", roleBlock),
			Policies: nil,
		}

		if inlineBlock := roleBlock.GetBlock("inline_policy"); inlineBlock.IsNotNil() {
			if policy, err := parsePolicy(inlineBlock, modules); err == nil {
				role.Policies = append(role.Policies, policy)
			}
		}

		roleMap[roleBlock.ID()] = role
	}

	return roleMap
}
