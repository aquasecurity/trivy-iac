package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"golang.org/x/exp/maps"
)

func adaptGroups(modules terraform.Modules) []iam.Group {

	groupMap := mapGroups(modules)

	groupBlockIDs := maps.Keys(groupMap)

	if groupBlockID, policy, ok := applyForDependentResource(
		modules, groupBlockIDs, "name", "aws_iam_group_policy", "group", findPolicy(modules),
	); ok && policy != nil {
		groupMap[groupBlockID].Policies = append(groupMap[groupBlockID].Policies, *policy)
	}

	if groupBlockID, policy, ok := applyForDependentResource(
		modules, groupBlockIDs, "name", "aws_iam_group_policy_attachment", "group", findAttachmentPolicy(modules),
	); ok && policy != nil {
		groupMap[groupBlockID].Policies = append(groupMap[groupBlockID].Policies, *policy)
	}

	var output []iam.Group
	for _, group := range groupMap {
		output = append(output, *group)
	}
	return output
}

func mapGroups(modules terraform.Modules) map[string]*iam.Group {
	groupMap := make(map[string]*iam.Group)
	for _, groupBlock := range modules.GetResourcesByType("aws_iam_group") {
		groupMap[groupBlock.ID()] = &iam.Group{
			Metadata: groupBlock.GetMetadata(),
			Name:     groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock),
			Users:    nil,
			Policies: nil,
		}
	}
	return groupMap
}
