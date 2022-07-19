package parser

import (
	"fmt"
	"testing"
)

func TestAntlrRun(t *testing.T) {
	ap := NewAntlrParser("MyParser")
	ap.Parse()
	fmt.Println(ap.Listener.SubTrees)
}
