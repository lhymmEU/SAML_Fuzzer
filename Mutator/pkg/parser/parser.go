package parser

import (
	"github.com/antlr/antlr4/runtime/Go/antlr"
	"xmlMutator/pkg/helpers"
	parser "xmlMutator/xmlGrammar"
)
import  "golang.org/x/exp/slices"


// The parser object

type MyAntlrParser struct {
	name string
	Listener *MyListener
}

func NewAntlrParser(name string) *MyAntlrParser {
	return &MyAntlrParser{
		name:     name,
		Listener: NewMyListener(),
	}
}

// Define the parser outputs


/*
Our own parse tree listener implementation
 */

/*
	Define the type.
	A listener should only contain the basic parsed information.
	Any interpretation or post-processed info should not be presented in this struct.
*/

type MyListener struct {
	*parser.BaseXMLParserListener
	strategy string
	Attr map[string][]string
	Terminals []string
	SubTrees []string
	Contents []string
	TagNames []string
}

// Define a constructor

func NewMyListener() *MyListener {
	return &MyListener{
		BaseXMLParserListener: new(parser.BaseXMLParserListener),
		Attr: map[string][]string{},
	}
}

// Implement the interfaces of *parser.BaseXMLParserListener


func (ml *MyListener) VisitTerminal(ctx antlr.TerminalNode) {
	ml.Terminals = append(ml.Terminals, ctx.GetText())
}

// This function will return every sub-tree visited,
// very useful for tree-mutation algorithm.

func (ml *MyListener) ExitElement(ctx *parser.ElementContext) {
	ml.SubTrees = append(ml.SubTrees, ctx.GetText())
}

// This function will return every attribute visited,
// very useful for value-locking algorithm.

func (ml *MyListener) EnterAttribute(ctx *parser.AttributeContext) {
		r := helpers.ParseAttributes(ctx.GetText())
		if !slices.Contains(ml.Attr[r[0]], r[1]) {
			ml.Attr[r[0]] = append(ml.Attr[r[0]], r[1])
		}
}

func (ml *MyListener) EnterChardata(ctx *parser.ChardataContext) {
	if !slices.Contains(ml.Contents, ctx.GetText()) {
		ml.Contents = append(ml.Contents, ctx.GetText())
	}
}

// TODO: for now, can only process xml file in the form of a string. (without indentation and so on.)
/*
	The function AntlrRun should generate 4 files, and one string slice.
	The files should be: (the actual generation of 2-4 is done in the tree listener)
		1. tag_name.txt ✅
		2. attributes.txt ✅
		3. content_val.txt ✅
		4. terminals.txt ✅

	The string slice should contain sub-tree masks in the form of:
		["start1-end1", "start2-end2"]
 */

func (ap *MyAntlrParser) Parse(seed string) {

	input, _ := antlr.NewFileStream(seed)
	lexer := parser.NewXMLLexer(input)
	stream := antlr.NewCommonTokenStream(lexer, 0)
	p := parser.NewXMLParser(stream)
	p.AddErrorListener(antlr.NewDiagnosticErrorListener(true))
	p.BuildParseTrees = true
	// In the case of XML, p.Document() is the same function as p.Json() in the case of json.
	tree := p.Document()
	antlr.ParseTreeWalkerDefault.Walk(ap.Listener, tree)

	ap.Listener.tagNameGen()
}

/*
	This function:
		1. Read-in the file "terminals.txt"
		2. Extract all the tag names and write them to a file "tag_name.txt"
 */

func (ml *MyListener) tagNameGen() {
	flag := false
	for _, terminal := range ml.Terminals {
		if terminal == "<" {
			flag = true
			continue
		}
		if flag && terminal != "/" && !slices.Contains(ml.TagNames, terminal) {
			ml.TagNames = append(ml.TagNames, terminal)
		}
		flag = false
	}

}
