package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-iac/pkg/scanners/cloudformation/cftypes"
)

type Parameter struct {
	inner parameterInner
}

type parameterInner struct {
	Type    string      `yaml:"Type"`
	Default interface{} `yaml:"Default"`
}

func (p *Parameter) UnmarshalYAML(node *yaml.Node) error {
	return node.Decode(&p.inner)
}

func (p *Parameter) UnmarshalJSONWithMetadata(node jfather.Node) error {
	return node.Decode(&p.inner)
}

func (p *Parameter) Type() cftypes.CfType {
	switch p.inner.Type {
	case "Boolean":
		return cftypes.Bool
	case "String":
		return cftypes.String
	case "Integer":
		return cftypes.Int
	default:
		return cftypes.String
	}
}

func (p *Parameter) Default() interface{} {
	return p.inner.Default
}

func (p *Parameter) UpdateDefault(inVal interface{}) {
	passedVal := inVal.(string)

	switch p.inner.Type {
	case "Boolean":
		p.inner.Default, _ = strconv.ParseBool(passedVal)
	case "String":
		p.inner.Default = passedVal
	case "Integer":
		p.inner.Default, _ = strconv.Atoi(passedVal)
	default:
		p.inner.Default = passedVal
	}
}

type Parameters map[string]any

func (p *Parameters) Merge(other Parameters) {
	for k, v := range other {
		(*p)[k] = v
	}
}

func (p *Parameters) UnmarshalJSON(data []byte) error {
	(*p) = make(Parameters)

	if len(data) == 0 {
		return nil
	}

	// CodePipeline like format
	switch {
	case data[0] == '{' && data[len(data)-1] == '}':
		var params struct {
			Params map[string]any `json:"Parameters"`
		}

		if err := json.Unmarshal(data, &params); err != nil {
			return err
		}

		(*p) = params.Params
	case data[0] == '[' && data[len(data)-1] == ']':
		{
			var params []string

			// Original format
			if err := json.Unmarshal(data, &params); err == nil {
				for _, param := range params {
					parts := strings.Split(param, "=")
					if len(parts) != 2 {
						break
					}
					(*p)[parts[0]] = parts[1]
				}
				return nil
			}

			// CloudFormation like format
			var cfparams []struct {
				ParameterKey   string `json:"ParameterKey"`
				ParameterValue string `json:"ParameterValue"`
			}

			if err := json.Unmarshal(data, &cfparams); err != nil {
				return err
			}

			for _, param := range cfparams {
				(*p)[param.ParameterKey] = param.ParameterValue
			}
		}
	default:
		return fmt.Errorf("unsupported parameters format")
	}

	return nil
}
