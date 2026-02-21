// Package generate holds helper function for the code generation that we use.
package generate

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"reflect"
	"slices"
)

var exclude = []string{""}

var FlagDebug = flag.Bool("debug", false, "Emit the non-formatted code to standard output and do not write it to a file.")

// EmptyData are RR that don't have rdata (or are embedding another type) and as such do not have an entry in rdata/rdata.go
var EmptyData = []string{
	"ANY", "AVC", "AXFR", "CDNSKEY", "CDS", "CLA", "DELEGPARAM", "DLV", "HTTPS",
	"IXFR", "KEY", "NXNAME", "NXT", "OPT", "SIG", "SPF", "RESINFO", "WALLET",
}

var Popular = []string{"A", "AAAA", "NS", "CNAME", "DNSKEY", "DS", "RRSIG", "DELEG", "MX", "TXT", "NSEC", "NSEC3"}

// Ast returns the *ast.File of file or an error.
func Ast(file string) (f *ast.File, t *token.FileSet, err error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, parser.AllErrors|parser.ParseComments|parser.SkipObjectResolution)
	return node, fset, err
}

// Types returns all types names from the file that are exported.
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
							if !slices.Contains(exclude, typeSpec.Name.Name) {
								// prepend if popular
								if slices.Contains(Popular, typeSpec.Name.Name) {
									types = append([]string{typeSpec.Name.Name}, types...)
								} else {
									types = append(types, typeSpec.Name.Name)
								}
							}
						}
					}
				}
			}
		}
	}
	return types, nil
}

// Fields returns the export type names and the field's names. Each name is prefixed with "rr.".
func Fields(file string) (map[string][]string, error) {
	node, _, err := Ast(file)
	if err != nil {
		return nil, err
	}

	types := map[string][]string{}
	for _, decl := range node.Decls {
		declType := reflect.TypeOf(decl)

		if declType.String() == "*ast.GenDecl" {
			genDecl := decl.(*ast.GenDecl)
			if genDecl.Tok == token.TYPE {
				for _, spec := range genDecl.Specs {
					if typeSpec, ok := spec.(*ast.TypeSpec); ok {
						if typeSpec.Name.IsExported() {
							types[typeSpec.Name.Name] = fields(typeSpec.Type)
						}
					}
				}
			}
		}
	}
	return types, nil
}

func fields(node ast.Node) []string {
	fields := []string{}
	switch n := node.(type) {
	case *ast.StructType:
		for _, field := range n.Fields.List {
			for _, f := range field.Names {
				if f.String() == "Hdr" {
					continue
				}
				fields = append(fields, "rr."+f.String())
			}
		}
	}
	return fields
}

// FilterTypeSpecs filters the type specs on name.
func FilterTypeSpecs(typeSpecs []*ast.TypeSpec, names []string) []*ast.TypeSpec {
	filtered := []*ast.TypeSpec{}
	for i := range typeSpecs {
		if slices.Contains(names, typeSpecs[i].Name.String()) {
			filtered = append(filtered, typeSpecs[i])
		}
	}
	return filtered
}

// StructTypeSpecs returns the struct types from file that can be inspected for the struct tags.
func StructTypeSpecs(file string) ([]*ast.TypeSpec, error) {
	node, _, err := Ast(file)
	if err != nil {
		return nil, err
	}
	structs := []*ast.TypeSpec{}

	ast.Inspect(node, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		if _, ok := typeSpec.Type.(*ast.StructType); !ok {
			return true
		}

		if !typeSpec.Name.IsExported() {
			return true
		}

		structs = append(structs, typeSpec)
		return true
	})
	return structs, nil
}

func Write(b *bytes.Buffer, out string) {
	formatted, err := format.Source(b.Bytes())
	if err != nil {
		b.WriteTo(os.Stderr)
		log.Fatalf("Failed to generate %s: %v", out, err)
	}

	if *FlagDebug {
		fmt.Print(string(formatted))
		return
	}

	if err := os.WriteFile(out, formatted, 0640); err != nil {
		log.Fatalf("Failed to generate %s: %v", out, err)
	}
}

func IsEmbedded(strct *ast.StructType) bool {
	if len(strct.Fields.List) == 1 {
		return strct.Fields.List[0].Type != nil && len(strct.Fields.List[0].Names) == 0
	}
	return false
}
