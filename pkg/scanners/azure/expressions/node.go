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
	if f, ok := e.val.(Expression); ok {
		return f.Evaluate(deploymentProvider)
	}
	return e.val
}

func (e expressionValue) Evaluate1(generalFuncs map[string]func(...interface{}) interface{}) interface{} {
	if f, ok := e.val.(Expression); ok {
		return f.Evaluate1(generalFuncs)
	}
	return e.val
}

type Expression struct {
	Name string
	Args []Node
}

func (f Expression) Evaluate(deploymentProvider functions.DeploymentData) interface{} {
	args := make([]interface{}, len(f.Args))
	for i, arg := range f.Args {
		args[i] = arg.Evaluate(deploymentProvider)
	}

	return functions.Evaluate(deploymentProvider, f.Name, args...)
}

func (f Expression) Evaluate1(generalFuncs map[string]func(...interface{}) interface{}) interface{} {
	args := make([]interface{}, len(f.Args))
	for i, arg := range f.Args {
		args[i] = arg.Evaluate1(generalFuncs)
	}

	return functions.Evaluate1(generalFuncs, f.Name, args...)
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
	funcNode := &Expression{
		Name: tw.pop().Data.(string),
	}
	tokenCloseParenCount := 0

	for tw.hasNext() {
		token := tw.pop()
		if token == nil {
			break
		}

		switch token.Type {
		case TokenCloseParen:
			if funcNode.Name != "parameters" {
				return funcNode
			} else if tokenCloseParenCount == 1 {
				tw.unPop()
				return funcNode
			}
			tokenCloseParenCount++
		case TokenComma:
			if funcNode.Name == "parameters" {
				return funcNode
			}
		case TokenName:
			if tw.peek().Type == TokenOpenParen {
				//  this is a function, unwind 1
				tw.unPop()
				funcNode.Args = append(funcNode.Args, newFunctionNode(tw))
			} else if funcNode.Name == "parameters" {
				funcNode.Args = append(funcNode.Args, expressionValue{token.Data})
			}
		case TokenLiteralString, TokenLiteralInteger, TokenLiteralFloat:
			funcNode.Args = append(funcNode.Args, expressionValue{token.Data})
		case TokenDot, TokenOpenBracket, TokenCloseBracket:
			if funcNode.Name == "parameters" {
				funcNode.Args = append(funcNode.Args, expressionValue{token.Data})
			}
		}

	}
	return funcNode
}
