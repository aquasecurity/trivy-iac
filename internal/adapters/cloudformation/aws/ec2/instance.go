package ec2

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy-iac/pkg/scanners/cloudformation/parser"
)

func getInstances(ctx parser.FileContext) (instances []ec2.Instance) {

	instanceResources := ctx.GetResourcesByType("AWS::EC2::Instance")

	for _, r := range instanceResources {
		instance := ec2.Instance{
			Metadata: r.Metadata(),
			// metadata not supported by CloudFormation at the moment -
			// https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/655
			MetadataOptions: ec2.MetadataOptions{
				Metadata:     r.Metadata(),
				HttpTokens:   defsecTypes.StringDefault("optional", r.Metadata()),
				HttpEndpoint: defsecTypes.StringDefault("enabled", r.Metadata()),
			},
			UserData:        r.GetStringProperty("UserData"),
			SecurityGroups:  nil,
			RootBlockDevice: nil,
			EBSBlockDevices: nil,
		}
		blockDevices := getBlockDevices(r)
		for i, device := range blockDevices {
			copyDevice := device
			if i == 0 {
				instance.RootBlockDevice = copyDevice
				continue
			}
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, device)
		}
		instances = append(instances, instance)
	}

	return instances
}

func getBlockDevices(r *parser.Resource) []*ec2.BlockDevice {
	var blockDevices []*ec2.BlockDevice

	devicesProp := r.GetProperty("BlockDeviceMappings")

	if devicesProp.IsNil() {
		return blockDevices
	}

	for _, d := range devicesProp.AsList() {
		device := &ec2.BlockDevice{
			Metadata:  d.Metadata(),
			Encrypted: d.GetBoolProperty("Ebs.Encrypted"),
		}

		blockDevices = append(blockDevices, device)
	}

	return blockDevices
}
