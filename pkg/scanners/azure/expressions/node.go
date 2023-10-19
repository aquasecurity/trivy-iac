package expressions

import (
	"github.com/wuwwlwwl/trivy-iac/pkg/scanners/azure/functions"
)

type Node interface {
	Evaluate(deploymentProvider functions.DeploymentData) interface{}
	Evaluate1(generalFuncs map[string]func(...interface{}) interface{}) interface{}
}

type expressionValue struct {
	val interface{}
}

func (e expressionValue) Evaluate(deploymentProvider functions.DeploymentData) interface{} {
	if f, ok := e.val.(expression); ok {
		return f.Evaluate(deploymentProvider)
	}
	return e.val
}

func (e expressionValue) Evaluate1(generalFuncs map[string]func(...interface{}) interface{}) interface{} {
	if f, ok := e.val.(expression); ok {
		return f.Evaluate1(generalFuncs)
	}
	return e.val
}

type expression struct {
	name string
	args []Node
}

func (f expression) Evaluate(deploymentProvider functions.DeploymentData) interface{} {
	args := make([]interface{}, len(f.args))
	for i, arg := range f.args {
		args[i] = arg.Evaluate(deploymentProvider)
	}

	return functions.Evaluate(deploymentProvider, f.name, args...)
}

func (f expression) Evaluate1(generalFuncs map[string]func(...interface{}) interface{}) interface{} {
	args := make([]interface{}, len(f.args))
	for i, arg := range f.args {
		args[i] = arg.Evaluate1(generalFuncs)
	}

	return functions.Evaluate1(generalFuncs, f.name, args...)
}

func NewExpressionTree(code string) (Node, error) {
	tokens, err := lex(code)
	if err != nil {
		return nil, err
	}

	// create a walker for the nodes
	tw := newTokenWalker(tokens)

	// generate the root function
	return newFunctionNode(tw), nil
}

func newFunctionNode(tw *tokenWalker) Node {
	funcNode := &expression{
		name: tw.pop().Data.(string),
	}
	tokenCloseParenCount := 0
	tokenOpenBracketCount := 0

	for tw.hasNext() {
		token := tw.pop()
		if token == nil {
			break
		}

		switch token.Type {
		case TokenCloseParen:
			if funcNode.name != "parameters" && funcNode.name != "variables" {
				return funcNode
			} else if tokenCloseParenCount == 1 {
				tw.unPop()
				return funcNode
			}
			tokenCloseParenCount++
		case TokenComma:
			if funcNode.name == "parameters" || funcNode.name == "variables" {
				return funcNode
			}
		case TokenName:
			if tw.peek().Type == TokenOpenParen {
				//  this is a function, unwind 1
				tw.unPop()
				funcNode.args = append(funcNode.args, newFunctionNode(tw))
			} else {
				funcNode.args = append(funcNode.args, expressionValue{token.Data})
			}
		case TokenLiteralString, TokenLiteralInteger, TokenLiteralFloat:
			funcNode.args = append(funcNode.args, expressionValue{token.Data})
		case TokenCloseBracket:
			if funcNode.name == "parameters" || funcNode.name == "variables" {
				if tokenOpenBracketCount == 0 {
					tw.unPop()
					return funcNode
				}
				funcNode.args = append(funcNode.args, expressionValue{token.Data})
			}
		case TokenOpenBracket:
			if funcNode.name == "parameters" || funcNode.name == "variables" {
				funcNode.args = append(funcNode.args, expressionValue{token.Data})
				tokenOpenBracketCount++
			}
		case TokenDot:
			if funcNode.name == "parameters" || funcNode.name == "variables" {
				funcNode.args = append(funcNode.args, expressionValue{token.Data})
			}
		}

	}
	return funcNode
}
