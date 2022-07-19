package mutator

import (
	"testing"
	"xmlMutator/pkg/parser"
)

/*func TestInit(t *testing.T) {
	myMutator := Init("Mine", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/config/mutationConfig.json", "myTreeConfig")
	fmt.Println("The name is: ", myMutator.config.Name)
	fmt.Println("The configs are: ", myMutator.config.MaxIteration)
	fmt.Println("The algo is: ", myMutator.config.Algo)
	fmt.Println("The mutation pool is: ", myMutator.mp)
}*/

func TestMutator_Mutate(t *testing.T) {
	myParser := parser.NewAntlrParser("testing")
	myMutator := Init("Mine", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/config/mutationConfig.json", "myPositionConfig")
	myParser.Parse()
	myMutator.Mutate(myParser.Listener)
}
