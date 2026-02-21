//go:build ignore

// string_generate generates zstring.go which houses the StringToHandler map.

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/generate"
	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/parser"
	"github.com/mmarkdown/mmark/v2/mparser"
	"github.com/mmarkdown/mmark/v2/render/man"
)

const format = `%%%%%%
title = "%s 7"
area = "atomdns handlers"
workgroup = "atomdns authors"
%%%%%%

`

func main() {
	handlers, err := generate.Handlers("handlers")
	if err != nil {
		log.Fatal(err)
	}
	handlers = append(handlers, []string{"import", "global"}...)
	for _, h := range handlers {
		h = strings.ToLower(h)
		readme := "handlers/" + h + "/README.md"
		b, err := os.ReadFile(readme)
		if err != nil {
			log.Printf("Failed to read %q: %s", readme, err)
			continue
		}
		header := fmt.Sprintf(format, h)
		b = append([]byte(header), b...)

		p := parser.NewWithExtensions(parser.FencedCode | parser.DefinitionLists | parser.Tables)
		p.Opts = parser.Options{
			ParserHook: func(data []byte) (ast.Node, []byte, int) { return mparser.Hook(data) },
			Flags:      parser.FlagsNone,
		}
		doc := markdown.Parse(b, p)
		renderer := man.NewRenderer(man.RendererOptions{})
		md := markdown.Render(doc, renderer)
		os.WriteFile(fmt.Sprintf("man/atomdns-%s.7", h), md, 0644)
	}
	// atomdns.1 and confile.5
	b, err := os.ReadFile("man/atomdns.1.md")
	if err != nil {
		return
	}
	header := `%%%
title = "atomdns 1"
area = "atomdns"
workgroup = "atomdns authors"
%%%

`
	b = append([]byte(header), b...)
	p := parser.NewWithExtensions(parser.FencedCode | parser.DefinitionLists | parser.Tables)
	p.Opts = parser.Options{
		ParserHook: func(data []byte) (ast.Node, []byte, int) { return mparser.Hook(data) },
		Flags:      parser.FlagsNone,
	}
	doc := markdown.Parse(b, p)
	renderer := man.NewRenderer(man.RendererOptions{})
	md := markdown.Render(doc, renderer)
	os.WriteFile("man/atomdns.1", md, 0644)

	b, err = os.ReadFile("man/atomdns-conffile.5.md")
	if err != nil {
		return
	}
	header = `%%%
title = "conffle 5"
area = "atomdns"
workgroup = "atomdns authors"
%%%

`
	b = append([]byte(header), b...)
	p = parser.NewWithExtensions(parser.FencedCode | parser.DefinitionLists | parser.Tables)
	p.Opts = parser.Options{
		ParserHook: func(data []byte) (ast.Node, []byte, int) { return mparser.Hook(data) },
		Flags:      parser.FlagsNone,
	}
	doc = markdown.Parse(b, p)
	renderer = man.NewRenderer(man.RendererOptions{})
	md = markdown.Render(doc, renderer)
	os.WriteFile("man/atomdns-conffile.5", md, 0644)
}
