package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func adaptGroups(modules terraform.Modules) []iam.Group {

	var output []iam.Group

	for groupBlockID, group := range mapGroups(modules) {
		if policy, ok := applyForDependentResource(
			modules, groupBlockID, "name", "aws_iam_group_policy", "group", findPolicy(modules),
		); ok && policy != nil {
			group.Policies = append(group.Policies, *policy)
		}

		if policy, ok := applyForDependentResource(
			modules, groupBlockID, "name", "aws_iam_group_policy_attachment", "group", findAttachmentPolicy(modules),
		); ok && policy != nil {
			group.Policies = append(group.Policies, *policy)
		}
		output = append(output, group)
	}
	return output
}

func mapGroups(modules terraform.Modules) map[string]iam.Group {
	groupMap := make(map[string]iam.Group)
	for _, groupBlock := range modules.GetResourcesByType("aws_iam_group") {
		groupMap[groupBlock.ID()] = iam.Group{
			Metadata: groupBlock.GetMetadata(),
			Name:     groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock),
			Users:    nil,
			Policies: nil,
		}
	}
	return groupMap
}
