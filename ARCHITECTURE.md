# Architecture

This document aims to answer the question *Where is the code that does X?*

## Project Layout

The directory structure is broken down as follows:

- `avd_docs/` - The source for the [AVD documentation](https://aquasecurity.github.io/avd/).
- `cmd/` - These CLI tools are primarily used during development for end-to-end testing without needing to pull the library into trivy/tfsec etc.
- `internal/adapters` - Adapters take input - such as a Terraform file or an AWS account - and _adapt_ it to a common format that can be used by the rules engine.
- `pkg/detection` - Used for sniffing file types from both file name and content. This is done so that we can determine the type of file we're dealing with and then pass it to the correct parser.
- `pkg/extrafs` - Wraps `os.DirFS` to provide a filesystem that can also resolve symlinks.
- `pkg/formatters` - Used to format scan results in specific formats, such as JSON, CheckStyle, CSV, SARIF, etc.
- `pkg/rego` - A package for evaluating Rego rules against given inputs.
- `pkg/rules` - This package exposes internal rules, and imports them accordingly (see _rules.go_).
- `pkg/scanners` - Scanners for various inputs. For example, the `terraform` scanner will scan a Terraform directory and return a list of resources.
- `pkg/types` - Useful types. Our types wrap a simple data type (e.g. `bool`) and add various metadata to it, such as file name and line number where it was defined.
- `test` - Integration tests and other high-level tests that require a full build of the project.
