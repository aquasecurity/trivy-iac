package azure

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/azure/expressions"
)

type Resolver interface {
	ResolveExpression(expression Value) Value
	SetDeployment(d *Deployment)
}

func NewResolver() Resolver {
	return &resolver{}
}

type resolver struct {
	deployment *Deployment
}

func (r *resolver) SetDeployment(d *Deployment) {
	r.deployment = d
}

func (r *resolver) ResolveExpression(expression Value) Value {
	if expression.Kind != KindExpression {
		return expression
	}
	if r.deployment == nil {
		panic("cannot resolve expression on nil deployment")
	}
	code := expression.AsExpressionString()

	resolved, err := r.resolveExpressionString(code, expression.GetMetadata())
	if err != nil {
		expression.Kind = KindUnresolvable
		return expression
	}
	return resolved
}

func (r *resolver) resolveExpressionString(code string, metadata defsecTypes.Metadata) (Value, error) {
	et, err := expressions.NewExpressionTree(code)
	if err != nil {
		return NullValue, err
	}

	evaluatedValue := et.Evaluate(r.deployment)
	return NewValue(evaluatedValue, metadata), nil
}
