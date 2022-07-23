package mutator

import (
	"fmt"
	"testing"
)

/*func TestInit(t *testing.T) {
	myMutator := Init("Mine", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/config/mutationConfig.json", "myTreeConfig")
	fmt.Println("The name is: ", myMutator.config.Name)
	fmt.Println("The configs are: ", myMutator.config.MaxIteration)
	fmt.Println("The algo is: ", myMutator.config.Algo)
	fmt.Println("The mutation pool is: ", myMutator.mp)
}*/

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

	expectInitial := []string{"<name>This is initial doc 1</name>", "<name>This is initial doc 2</name>", "<name>This is initial doc 3</name>"}
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
