package connector

import (
	"fmt"
	"testing"
)

func TestInit(t *testing.T) {
	myConnector := Init("myC", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/pkg/mutationPool", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/pkg/connector")
	fmt.Println(myConnector.mutationPoolPath)
	myConnector.Send()
}
