package embed

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"

	"github.com/aquasecurity/trivy-iac/pkg/rego"
	"github.com/aquasecurity/trivy-iac/pkg/rules"
	rules2 "github.com/aquasecurity/trivy-policies/rules"
)

func init() {

	modules, err := LoadEmbeddedPolicies()
	if err != nil {
		// we should panic as the policies were not embedded properly
		panic(err)
	}
	loadedLibs, err := LoadEmbeddedLibraries()
	if err != nil {
		panic(err)
	}
	for name, policy := range loadedLibs {
		modules[name] = policy
	}

	RegisterRegoRules(modules)
}

func RegisterRegoRules(modules map[string]*ast.Module) {
	ctx := context.TODO()

	schemaSet, _, _ := rego.BuildSchemaSetFromPolicies(modules, nil, nil)

	compiler := ast.NewCompiler().
		WithSchemas(schemaSet).
		WithCapabilities(nil).
		WithUseTypeCheckAnnotations(true)

	compiler.Compile(modules)
	if compiler.Failed() {
		// we should panic as the embedded rego policies are syntactically incorrect...
		panic(compiler.Errors)
	}

	retriever := rego.NewMetadataRetriever(compiler)
	for _, module := range modules {
		metadata, err := retriever.RetrieveMetadata(ctx, module)
		if err != nil {
			continue
		}
		if metadata.AVDID == "" {
			continue
		}
		rules.Register(
			metadata.ToRule(),
			nil,
		)
	}
}

func LoadEmbeddedPolicies() (map[string]*ast.Module, error) {
	return LoadPoliciesFromDirs(rules2.EmbeddedPolicyFileSystem, ".")
}

func LoadEmbeddedLibraries() (map[string]*ast.Module, error) {
	return LoadPoliciesFromDirs(rules2.EmbeddedLibraryFileSystem, ".")
}

func IsRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func IsDotFile(name string) bool {
	return strings.HasPrefix(name, ".")
}

func sanitisePath(path string) string {
	vol := filepath.VolumeName(path)
	path = strings.TrimPrefix(path, vol)
	return strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(path), "./"), "/")
}

func LoadPoliciesFromDirs(target fs.FS, paths ...string) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for _, path := range paths {
		if err := fs.WalkDir(target, sanitisePath(path), func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			if strings.HasSuffix(filepath.Dir(filepath.ToSlash(path)), "policies/advanced/optional") {
				return fs.SkipDir
			}

			if !IsRegoFile(info.Name()) || IsDotFile(info.Name()) {
				return nil
			}
			data, err := fs.ReadFile(target, filepath.ToSlash(path))
			if err != nil {
				return err
			}
			module, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{
				ProcessAnnotation: true,
			})
			if err != nil {
				// s.debug.Log("Failed to load module: %s, err: %s", filepath.ToSlash(path), err.Error())
				return err
			}
			modules[path] = module
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return modules, nil
}
