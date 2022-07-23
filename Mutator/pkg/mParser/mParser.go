package mParser

import (
	"fmt"
	"xmlMutator/pkg/parser"
)

/*
	For now, this package will do nothing,
	if in the future, the required data structure of a mutation algorithm changed,
	the changing process should be written here.
 */

func Parse() *parser.MyAntlrParser {
	myParser := parser.NewAntlrParser("experiment")
	myParser.Parse()
	fmt.Println("The input file has been parsed into a position-aware format.")
	return myParser
}
