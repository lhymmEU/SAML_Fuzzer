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

func TestExtractProtected(t *testing.T) {
	fmt.Println("\nStart testing... extractProtected()")
	myMutator := Init("testExtractProtected", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")
	myParser := parser.NewAntlrParser("testIdentifyPositions")
	myParser.Parse("/Users/lhymm/SAML_Fuzzer/Mutator/seeds/testing/test.xml")

	fmt.Println("Subtrees are: ", myParser.Listener.SubTrees)
	result, protectedID := myMutator.extractProtected(myParser.Listener.SubTrees)
	fmt.Println("The extracted part is: ", result)
	fmt.Println("The protected id is: ", protectedID)

	fmt.Println("\nEnd testing... extractProtected()")
}

func TestBuildPayload(t *testing.T) {
	fmt.Println("\nStart testing... buildPayload()")
	myMutator := Init("testBuildPayload", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")

	expected := "<nameID=\"attack\"><justFun/>This is initial doc 1</name>"
	result := myMutator.buildPayload("<nameID=\"protected\"><justFun/>This is initial doc 1</name>", "ID=\"protected\"")
	if result != expected {
		t.Fatalf("Testing failed -- buildPayload()")
	}
	fmt.Println("The payload built is: ", result)

	fmt.Println("\nEnd testing... buildPayload()")
}

func TestPositionMutate(t *testing.T) {
	fmt.Println("\nStart testing... positionMutate()")
	myMutator := Init("testPositionMutate", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")
	myParser := parser.NewAntlrParser("testIdentifyPositions")
	myParser.Parse("/Users/lhymm/SAML_Fuzzer/Mutator/seeds/testing/test.xml")

	payload := "<nameID=\"attack\"><justFun/>This is initial doc 1</name>"

	myMutator.positionMap = myMutator.identifyPositions(myParser.Listener)
	result, payloadPosition := myMutator.positionMutate(payload, myParser.Listener)
	fmt.Println("Mutation result is: ", result)
	fmt.Println("The position of payload is: ", payloadPosition)

	fmt.Println("\nEnd testing... positionMutate()")
}

func TestValidityCheck(t *testing.T) {
	fmt.Println("\nStart testing... validityCheck()")
	myMutator := Init("testValidityCheck()", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")
	r1 := myMutator.validityCheck("/Users/lhymm/SAML_Fuzzer/preFilterTools/samlSign/saml_response.xml", 0)
	r2 := myMutator.validityCheck("/Users/lhymm/SAML_Fuzzer/preFilterTools/xmlsectool/saml_response.xml", 1)
	r3 := myMutator.validityCheck("", 1000)
	r4 := myMutator.validityCheck("/Users/lhymm/SAML_Fuzzer/preFilterTools/samlSign/saml_response_invalid.xml", 0)
	r5 := myMutator.validityCheck("/Users/lhymm/SAML_Fuzzer/preFilterTools/samlSign/saml_response_invalid.xml", 1)
	fmt.Println("The results are: ", r1, r2, r3, r4, r5)

	fmt.Println("\nEnd testing... validityCheck()")
}
