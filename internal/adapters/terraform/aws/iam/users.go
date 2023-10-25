package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"golang.org/x/exp/maps"
)

func adaptUsers(modules terraform.Modules) []iam.User {
	userMap := mapUsers(modules)
	userBlockIDs := maps.Keys(userMap)

	if userBlockID, policy, ok := applyForDependentResource(
		modules, userBlockIDs, "name", "aws_iam_user_policy", "user", findPolicy(modules),
	); ok && policy != nil {
		userMap[userBlockID].Policies = append(userMap[userBlockID].Policies, *policy)
	}

	if userBlockID, policy, ok := applyForDependentResource(
		modules, userBlockIDs, "name", "aws_iam_user_policy_attachment", "user", findAttachmentPolicy(modules),
	); ok && policy != nil {
		userMap[userBlockID].Policies = append(userMap[userBlockID].Policies, *policy)
	}

	if roleBlockID, accessKey, ok := applyForDependentResource(modules, userBlockIDs, "name", "aws_iam_access_key", "user", func(resource *terraform.Block) iam.AccessKey {
		return adaptAccessKey(resource)
	}); ok {
		userMap[roleBlockID].AccessKeys = append(userMap[roleBlockID].AccessKeys, accessKey)
	}

	var output []iam.User
	for _, user := range userMap {
		output = append(output, *user)
	}
	return output
}

func mapUsers(modules terraform.Modules) map[string]*iam.User {
	userMap := make(map[string]*iam.User)
	for _, userBlock := range modules.GetResourcesByType("aws_iam_user") {
		userMap[userBlock.ID()] = &iam.User{
			Metadata:   userBlock.GetMetadata(),
			Name:       userBlock.GetAttribute("name").AsStringValueOrDefault("", userBlock),
			LastAccess: defsecTypes.TimeUnresolvable(userBlock.GetMetadata()),
		}
	}
	return userMap

}

func adaptAccessKey(block *terraform.Block) iam.AccessKey {

	active := defsecTypes.BoolDefault(true, block.GetMetadata())
	if activeAttr := block.GetAttribute("status"); activeAttr.IsString() {
		active = defsecTypes.Bool(activeAttr.Equals("Active"), activeAttr.GetMetadata())
	}
	return iam.AccessKey{
		Metadata:     block.GetMetadata(),
		AccessKeyId:  defsecTypes.StringUnresolvable(block.GetMetadata()),
		CreationDate: defsecTypes.TimeUnresolvable(block.GetMetadata()),
		LastAccess:   defsecTypes.TimeUnresolvable(block.GetMetadata()),
		Active:       active,
	}
}
