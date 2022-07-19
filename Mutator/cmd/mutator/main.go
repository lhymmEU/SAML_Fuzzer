package main

import (
	"fmt"
	"xmlMutator/pkg/mParser"
	"xmlMutator/pkg/parser"
)

func main() {
	myParser := parser.NewAntlrParser("Mine", "tree")
	myParser.Parse()
	mParser.Parse(myParser)
	fmt.Println(myParser.Listener)
	/*for i := 0; i < 10; i++ {
		filePath := "./results" + time.Now().String() + ".xml"
		leaf_mutator.LeafMutator(filePath, true)
	}*/
	/*for i := 0; i < 10; i++ {
		filePath := "./results" + time.Now().String() + ".xml"
		tree_mutator.TreeMutator(filePath)
	}*/
}
