package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"golang.org/x/exp/maps"
)

func adaptRoles(modules terraform.Modules) []iam.Role {

	roleMap := mapRoles(modules)
	roleBlockIDs := maps.Keys(roleMap)

	if roleBlockID, policy, ok := applyForDependentResource(
		modules, roleBlockIDs, "name", "aws_iam_role_policy", "role", findPolicy(modules),
	); ok && policy != nil {
		roleMap[roleBlockID].Policies = append(roleMap[roleBlockID].Policies, *policy)
	}

	if roleBlockID, policy, ok := applyForDependentResource(
		modules, roleBlockIDs, "name", "aws_iam_role_policy_attachment", "role", findAttachmentPolicy(modules),
	); ok && policy != nil {
		roleMap[roleBlockID].Policies = append(roleMap[roleBlockID].Policies, *policy)
	}

	var output []iam.Role
	for _, role := range roleMap {
		output = append(output, *role)
	}
	return output
}

func mapRoles(modules terraform.Modules) map[string]*iam.Role {
	roleMap := make(map[string]*iam.Role)
	for _, roleBlock := range modules.GetResourcesByType("aws_iam_role") {
		role := &iam.Role{
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
