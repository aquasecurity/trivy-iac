package azure

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/tomwright/dasel"
)

type Deployment struct {
	Metadata    types.Metadata
	TargetScope Scope
	Parameters  []Parameter
	Variables   []Variable
	Copy        *Copy
	Resources   []Resource
	Outputs     []Output
}

type Parameter struct {
	Variable
	Default    Value
	Decorators []Decorator
}

type Variable struct {
	Name  string
	Value Value
}

type Output Variable

type Resource struct {
	Metadata             types.Metadata
	Condition            Value
	APIVersion           Value
	Type                 Value
	Kind                 Value
	Name                 Value
	Location             Value
	Tags                 Value
	Sku                  Value
	DeploymentProperties DeploymentProperties
	Copy                 *Copy
	Properties           Value
	Resources            []Resource
}

type Copy struct {
	Name      Value
	Mode      Value
	BatchSize Value
	Count     Value
}

type DeploymentProperties struct {
	Mode                        Value
	ParameterValues             map[string]Value
	ExpressionEvaluationOptions *ExpressionEvaluationOptions
	Deployment                  *Deployment
}

type ExpressionEvaluationOptions struct {
	Scope Value
}

type PropertyBag struct {
	Metadata types.Metadata
	Data     map[string]Value
}

type Decorator struct {
	Name string
	Args []Value
}

type Scope string

const (
	ScopeResourceGroup Scope = "resourceGroup"
)

func (d *Deployment) GetResourcesByType(t string) []Resource {
	var resources []Resource
	for _, r := range d.Resources {
		if r.Type.AsString() == t {
			resources = append(resources, r)
		}
	}
	return resources
}

func (r *Resource) GetResourcesByType(t string) []Resource {
	var resources []Resource
	for _, res := range r.Resources {
		if res.Type.AsString() == t {
			resources = append(resources, res)
		}
	}
	return resources
}

func (d *Deployment) SetParameter(name string, value interface{}) error {
	for index, param := range d.Parameters {
		if param.Variable.Name == name {
			if v, ok := value.(Value); ok {
				d.Parameters[index].Variable.Value = v
			} else {
				d.Parameters[index].Variable.Value = NewValue(value, param.Value.GetMetadata())
			}

			return nil
		}
	}
	return fmt.Errorf("parameter %s not found in the deployment", name)
}

func (d *Deployment) GetParameter(name string) interface{} {

	parameterName := name
	propertyName := ""
	indexDot := strings.Index(name, ".")
	indexBracket := strings.Index(name, "[")
	index := indexDot
	if indexBracket < indexDot && indexBracket >= 0 {
		index = indexBracket
	}
	if index >= 0 {
		parameterName = name[:index]
		propertyName = name[index:]
		propertyName = strings.ReplaceAll(propertyName, "[", ".[")
	}

	for _, parameter := range d.Parameters {
		if parameter.Name == parameterName {
			value := parameter.Value.Raw()
			if propertyName == "" {
				return value
			}
			paramNode := dasel.New(value)
			result, err := paramNode.Query(propertyName)
			if err != nil {
				fmt.Printf("parse parameter %s failed, %v", name, err)
				return nil
			}
			return result.InterfaceValue()
		}
	}

	return nil
}

func (d *Deployment) GetVariable(variableName string) interface{} {

	resolver := resolver{
		deployment: d,
	}

	for _, variable := range d.Variables {
		if variable.Name == variableName {
			if variable.Value.Kind == KindExpression {
				value, err := resolver.resolveExpressionString(variable.Value.AsExpressionString(), types.NewTestMetadata())
				if err != nil {
					fmt.Printf("resolve expression %s failed, %v", variable.Value.AsExpressionString(), err)
					return nil
				}
				return value.Raw()
			}
			return variable.Value.Raw()
		}
	}
	return nil
}

func (d *Deployment) GetEnvVariable(envVariableName string) interface{} {

	if envVariable, exists := os.LookupEnv(envVariableName); exists {
		return envVariable
	}
	return nil
}

func (d *Deployment) GetOutput(outputName string) interface{} {

	for _, output := range d.Outputs {
		if output.Name == outputName {
			return output.Value.Raw()
		}
	}
	return nil
}

func (d *Deployment) GetDeployment() interface{} {

	type template struct {
		Schema         string                 `json:"$schema"`
		ContentVersion string                 `json:"contentVersion"`
		Parameters     map[string]interface{} `json:"parameters"`
		Variables      map[string]interface{} `json:"variables"`
		Resources      []interface{}          `json:"resources"`
		Outputs        map[string]interface{} `json:"outputs"`
	}

	type templateLink struct {
		URI string `json:"uri"`
	}

	type properties struct {
		TemplateLink      templateLink           `json:"templateLink"`
		Template          template               `json:"template"`
		TemplateHash      string                 `json:"templateHash"`
		Parameters        map[string]interface{} `json:"parameters"`
		Mode              string                 `json:"mode"`
		ProvisioningState string                 `json:"provisioningState"`
	}

	deploymentShell := struct {
		Name       string     `json:"name"`
		Properties properties `json:"properties"`
	}{
		Name: "Placeholder Deployment",
		Properties: properties{
			TemplateLink: templateLink{
				URI: "https://placeholder.com",
			},
			Template: template{
				Schema:         "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
				ContentVersion: "",
				Parameters:     make(map[string]interface{}),
				Variables:      make(map[string]interface{}),
				Resources:      make([]interface{}, 0),
				Outputs:        make(map[string]interface{}),
			},
		},
	}

	for _, parameter := range d.Parameters {
		deploymentShell.Properties.Template.Parameters[parameter.Name] = parameter.Value.Raw()
	}

	for _, variable := range d.Variables {
		deploymentShell.Properties.Template.Variables[variable.Name] = variable.Value.Raw()
	}

	for _, resource := range d.Resources {
		deploymentShell.Properties.Template.Resources = append(deploymentShell.Properties.Template.Resources, resource)
	}

	for _, output := range d.Outputs {
		deploymentShell.Properties.Template.Outputs[output.Name] = output.Value.Raw()
	}

	return deploymentShell
}
