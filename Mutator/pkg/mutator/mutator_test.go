package mutator

import (
	"fmt"
	"testing"
	"xmlMutator/pkg/parser"
)

func TestInit(t *testing.T) {
	fmt.Println("Start testing... Init()")

	myMutator := Init("myMutator", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/config/mutationConfig.json", "myPositionConfig")
	fmt.Println("My mutator's name is: ", myMutator.name)
	fmt.Println("My mutator's config is: ", myMutator.config)
	fmt.Println("My mutator's mutation pool is: ", myMutator.mp)
	fmt.Println("My mutator's position map is: ", myMutator.positionMap)

	fmt.Println("End testing... Init()!!!")
}

func TestFetchSeeds(t *testing.T) {
	fmt.Println("Start testing... fetchSeeds()")

	expectInitial := []string{"../../seeds/initial/initial.xml", "../../seeds/initial/initial2.xml", "../../seeds/initial/initial3.xml"}
	expectPhaseTwo := []string{"<name>This is phase two doc 1</name>", "<name>This is phase two doc 2</name>", "<name>This is phase two doc 3</name>"}

	resultInitial := fetchSeeds("initial")
	resultPhaseTwo := fetchSeeds("phaseTwo")

	for i := 0; i < 3; i++ {
		fmt.Printf("result initial %d is: %s\n", i, resultInitial[i])
		if resultInitial[i] != expectInitial[i] {
			t.Fatalf("fetchSeeds(initial) failed")
		}
		fmt.Printf("result phase two %d is: %s\n", i, resultPhaseTwo[i])
		if resultPhaseTwo[i] != expectPhaseTwo[i] {
			t.Fatalf("fetchSeeds(phaseTwo) failed")
		}
	}

	fmt.Println("End testing... fetchSeeds()!!!")
}

func TestIdentifyPositions(t *testing.T) {
	fmt.Println("\nStart testing... identifyPositions()")
	myMutator := Init("testIdentifyPositions", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")
	myParser := parser.NewAntlrParser("testIdentifyPositions")
	myParser.Parse("/Users/lhymm/SAML_Fuzzer/Mutator/seeds/testing/test.xml")

	positions := myMutator.identifyPositions(myParser.Listener)
	fmt.Println("terminals are: ", myParser.Listener.Terminals)
	fmt.Println("positions are: ", positions)

	fmt.Println("\nEnd testing... identifyPositions()")
}