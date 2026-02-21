package generate

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"reflect"
)

// Ast returns the *ast.File of file or an error.
func Ast(file string) (f *ast.File, t *token.FileSet, err error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, parser.AllErrors|parser.ParseComments|parser.SkipObjectResolution)
	return node, fset, err
}

// Handler returns all types names from file that are exported.
func Types(file string) ([]string, error) {
	node, _, err := Ast(file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %v", file, err)
	}

	types := []string{}
	for _, decl := range node.Decls {
		declType := reflect.TypeOf(decl)

		if declType.String() == "*ast.GenDecl" {
			genDecl := decl.(*ast.GenDecl)
			if genDecl.Tok == token.TYPE {
				for _, spec := range genDecl.Specs {
					if typeSpec, ok := spec.(*ast.TypeSpec); ok {
						if typeSpec.Name.IsExported() {
							types = append(types, typeSpec.Name.Name)
						}
					}
				}
			}
		}
	}
	return types, nil
}

func Write(b *bytes.Buffer, out string) {
	formatted, err := format.Source(b.Bytes())
	if err != nil {
		b.WriteTo(os.Stderr)
		log.Fatalf("Failed to generate %s: %v", out, err)
	}

	if err := os.WriteFile(out, formatted, 0640); err != nil {
		log.Fatalf("Failed to generate %s: %v", out, err)
	}
}
