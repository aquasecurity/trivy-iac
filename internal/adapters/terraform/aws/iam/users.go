package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func adaptUsers(modules terraform.Modules) []iam.User {

	var output []iam.User

	for userBlockID, user := range mapUsers(modules) {
		if policy, ok := applyForDependentResource(
			modules, userBlockID, "name", "aws_iam_user_policy", "user", findPolicy(modules),
		); ok && policy != nil {
			user.Policies = append(user.Policies, *policy)
		}

		if policy, ok := applyForDependentResource(
			modules, userBlockID, "name", "aws_iam_user_policy_attachment", "user", findAttachmentPolicy(modules),
		); ok && policy != nil {
			user.Policies = append(user.Policies, *policy)
		}

		if accessKey, ok := applyForDependentResource(
			modules, userBlockID, "name", "aws_iam_access_key", "user", adaptAccessKey,
		); ok {
			user.AccessKeys = append(user.AccessKeys, accessKey)
		}

		output = append(output, user)
	}

	return output
}

func mapUsers(modules terraform.Modules) map[string]iam.User {
	userMap := make(map[string]iam.User)
	for _, userBlock := range modules.GetResourcesByType("aws_iam_user") {
		userMap[userBlock.ID()] = iam.User{
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
