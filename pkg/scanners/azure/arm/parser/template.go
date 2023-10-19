package parser

import (
	"github.com/aquasecurity/defsec/pkg/types"
	types2 "github.com/wuwwlwwl/trivy-iac/pkg/scanners/azure"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/azure/arm/parser/armjson"
)

type Template struct {
	Metadata       types.Metadata          `json:"-"`
	Schema         types2.Value            `json:"$schema"`
	ContentVersion types2.Value            `json:"contentVersion"`
	APIProfile     types2.Value            `json:"apiProfile"`
	Parameters     map[string]Parameter    `json:"parameters"`
	Variables      map[string]types2.Value `json:"variables"`
	Functions      []Function              `json:"functions"`
	Resources      []Resource              `json:"resources"`
	Copy           *Copy                   `json:"copy"`
	Outputs        map[string]types2.Value `json:"outputs"`
}

type Parameter struct {
	Metadata     types.Metadata
	Type         types2.Value `json:"type"`
	DefaultValue types2.Value `json:"defaultValue"`
	MaxLength    types2.Value `json:"maxLength"`
	MinLength    types2.Value `json:"minLength"`
}

type Function struct{}

type Resource struct {
	Metadata types.Metadata `json:"-"`
	innerResource
}

func (t *Template) SetMetadata(m *types.Metadata) {
	t.Metadata = *m
}

func (r *Resource) SetMetadata(m *types.Metadata) {
	r.Metadata = *m
}

func (p *Parameter) SetMetadata(m *types.Metadata) {
	p.Metadata = *m
}

type innerResource struct {
	APIVersion         types2.Value       `json:"apiVersion"`
	Type               types2.Value       `json:"type"`
	Kind               types2.Value       `json:"kind"`
	Copy               *Copy              `json:"copy"`
	Name               types2.Value       `json:"name"`
	Location           types2.Value       `json:"location"`
	SubscriptionId     types2.Value       `json:"subscriptionId"`
	ResourceGroup      types2.Value       `json:"resourceGroup"`
	Condition          types2.Value       `json:"condition"`
	Tags               types2.Value       `json:"tags"`
	Sku                types2.Value       `json:"sku"`
	Properties         types2.Value       `json:"properties"`
	TemplateProperties TemplateProperties `json:"properties"`
	Resources          []Resource         `json:"resources"`
}

type Copy struct {
	Name      types2.Value `json:"name"`
	Mode      types2.Value `json:"mode"`
	BatchSize types2.Value `json:"batchSize"`
	Count     types2.Value `json:"count"`
}

type TemplateProperties struct {
	Mode                        types2.Value                 `json:"mode"`
	ExpressionEvaluationOptions *ExpressionEvaluationOptions `json:"expressionEvaluationOptions"`
	ParameterValues             map[string]ParameterValue    `json:"parameters"`
	Template                    *Template                    `json:"template"`
}

type ExpressionEvaluationOptions struct {
	Scope types2.Value `json:"scope"`
}

type ParameterValue struct {
	Value types2.Value `json:"value"`
}

func (v *Resource) UnmarshalJSONWithMetadata(node armjson.Node) error {

	if err := node.Decode(&v.innerResource); err != nil {
		return err
	}

	v.Metadata = node.Metadata()

	for _, comment := range node.Comments() {
		var str string
		if err := comment.Decode(&str); err != nil {
			return err
		}
		// TODO
		// v.Metadata.Comments = append(v.Metadata.Comments, str)
	}

	return nil
}
