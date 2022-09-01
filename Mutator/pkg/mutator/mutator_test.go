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
	fullProtected, _, _ := myMutator.extractProtected(myParser.Listener.SubTrees)
	fmt.Println("The fully protected part is: ", fullProtected)

	positions := myMutator.identifyPositions(myParser.Listener, fullProtected)
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
	_, result, protectedID := myMutator.extractProtected(myParser.Listener.SubTrees)
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
	myParser.Parse("/Users/lhymm/SAML_Fuzzer/Mutator/seeds/testing/special_test.xml")

	fullProtected, protected, protectedID := myMutator.extractProtected(myParser.Listener.SubTrees)
	payload := myMutator.buildPayload(protected, protectedID)
	myMutator.positionMap = myMutator.identifyPositions(myParser.Listener, fullProtected)
	result, payloadPosition, protectedPosition := myMutator.positionMutate(payload, fullProtected, myParser.Listener)
	fmt.Println("Mutation result is: ", result)
	fmt.Println("The position of payload is: ", payloadPosition)
	fmt.Println("The protected part is: ", protectedPosition)
	fmt.Println("Position map is: ", myMutator.positionMap)

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

func TestWriteMutatedSeed(t *testing.T) {
	fmt.Println("\nStart testing... writeMutatedSeed()")
	myMutator := Init("testWriteMutatedSeed()", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")
	myMutator.writeMutatedSeed("<test>I'm the test seed for phase one</test>", "phaseOne")
	myMutator.writeMutatedSeed("<test>I'm the test seed for phase two</test>", "phaseTwo")

	fmt.Println("\nEnd testing... writeMutatedSeed()")
}

func TestCalculateRelative(t *testing.T) {
	fmt.Println("\nStart testing... calculateRelative()")
	myMutator := Init("testWriteMutatedSeed()", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")

	payloadPosition := position{
		depth:          3,
		width:          4,
		insertionPoint: 0,
	}
	result := myMutator.calculateRelative(position{}, payloadPosition)
	fmt.Println("Result is: ", result)

	fmt.Println("\nEnd testing... calculateRelative()")
}

func TestWriteScoreBoard(t *testing.T) {
	fmt.Println("\nStart testing... writeScoreBoard()")
	myMutator := Init("testWriteScoreBoard()", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")

	rp := relativePosition{
		x: 1,
		y: 2,
	}
	rp2 := relativePosition{
		x: 2,
		y: 3,
	}
	myMutator.writeScoreBoard(rp, true, "")
	myMutator.writeScoreBoard(rp, false, "")
	myMutator.writeScoreBoard(rp2, false, "")
	myMutator.writeScoreBoard(rp2, false, "")

	fmt.Println("\nEnd testing... writeScoreBoard()")
}

func TestAnalyzeScoreBoard(t *testing.T) {
	fmt.Println("\nStart testing... analyzeScoreBoard()")
	myMutator := Init("testWriteScoreBoard()", "/Users/lhymm/SAML_Fuzzer/Mutator/config/mutationConfig.json", "myPositionConfig")

	rp := relativePosition{
		x: 1,
		y: 2,
	}
	rp2 := relativePosition{
		x: 2,
		y: 3,
	}
	myMutator.writeScoreBoard(rp, true, "")
	myMutator.writeScoreBoard(rp, false, "")
	myMutator.writeScoreBoard(rp2, false, "")
	myMutator.writeScoreBoard(rp2, false, "")

	fmt.Println("The result is: ", myMutator.analyzeScoreBoard(myMutator.board))
	fmt.Println("\nEnd testing... analyzeScoreBoard()")
}
