package parser

import (
	"fmt"
	"testing"
)

func TestNewAntlrParser(t *testing.T) {
	fmt.Println("\nStart testing... NewAntlrParser()")
	expected := "testNewParser"
	newParser := NewAntlrParser("testNewParser")
	result := newParser.name
	fmt.Println("New parser looks like: ", *newParser)

	if result != expected {
		t.Fatalf("Test failed -- NewAntlrParser()")
	}

	fmt.Println("\nEnd testing... NewAntlrParser()")
}

func TestParse(t *testing.T) {
	fmt.Println("\nStart testing... Parser()")
	testParser := NewAntlrParser("testParser")
	testParser.Parse("../../seeds/initial/initial.xml")
	fmt.Println("After parsing, the listener stores following values: ")
	fmt.Println("The strategy is: ", testParser.Listener.strategy)
	fmt.Println("The sub-trees are: ", testParser.Listener.SubTrees)
	fmt.Println("The tag names are: ", testParser.Listener.TagNames)
	fmt.Println("The attributes are: ", testParser.Listener.Attr)
	fmt.Println("The contents are: ", testParser.Listener.Contents)
	fmt.Println("The terminals are: ", testParser.Listener.Terminals)

	fmt.Println("\nEnd testing... Parser()")
}
