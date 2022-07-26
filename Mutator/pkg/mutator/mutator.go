package mutator

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"
	"xmlMutator/pkg/helpers"
	"xmlMutator/pkg/parser"
)

type Configs struct {
	Configs []MutationConfig
}

type MutationConfig struct {
	Name string			`json:"name"`
	Algo string			`json:"algo"`
	MaxIteration int	`json:"max_iteration"`
}

type mSeeds struct {
	name string // name of the seed file
	path string // path of the folder contains the seed file
	rank int
}

type mutationPool struct {
	mutatedSeeds []mSeeds
}

type positionMutator struct {
	name string
	config *MutationConfig
	mp *mutationPool
	positionMap []position
}

func Init(name string, configPath string, configName string) *positionMutator {
	var config Configs
	jsonFile, _ := os.Open(configPath)
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err := json.Unmarshal(byteValue, &config)
	if err != nil {
		fmt.Println("error is: ", err)
	}

	for i, c := range config.Configs {
		if c.Name == configName {
			return &positionMutator{
				name:  	name,
				config: &config.Configs[i],
				mp:     new(mutationPool),
			}
		}
	}

	fmt.Println("No configuration matched the given algorithm name, return nil.")

	return nil
}

func (m *positionMutator) Mutate(ml *parser.MyListener) {
	var s string
	switch m.config.Algo {
	case "tree":
		s = m.treeMutation(ml)
	case "leaf":
		//leafMutation()
	case "position":
		m.positionMutation()
	default:
		m.positionMutation()
	}

	// This part is to solve the issue of <Nameid="123">
	// TODO: should be replaced by an add seed function from package mutationPool
	for v, _ := range ml.Attr {
		s = helpers.XMLStringRefactor("", s, v)
	}
	helpers.WriteStringToFile(s, "./result.xml")
}

// Implementation of tree mutation algorithm

func (m *positionMutator) treeMutation(ml *parser.MyListener) string {
	subTrees := ml.SubTrees
	// the last string in a sub-tree slice is the file itself.
	xmlString := subTrees[len(subTrees)-1]
	fmt.Println("xmlString is: ", xmlString)

	for i := 0; i < m.config.MaxIteration; i++ {
		// seed the random generator
		rand.Seed(time.Now().UnixNano())
		// randomly pick a subTree string from []subTrees, exclude the last element
		original := rand.Intn(len(subTrees)-1)
		// seed it again
		rand.Seed(time.Now().UnixNano())
		// randomly choose an action: 0-do nothing; 1-delete; 2-replace; 3-add to front
		action := rand.Intn(4)
		switch action {
		case 0:
			continue
		case 1:
			start, end := subTreeIdentify(xmlString, subTrees[original])
			xmlString = xmlString[:start] + xmlString[end+1:]
			continue
		case 2:
			start, end := subTreeIdentify(xmlString, subTrees[original])
			rand.Seed(time.Now().UnixNano())
			replacement := subTrees[rand.Intn(len(subTrees))]
			xmlString = xmlString[:start] + replacement + xmlString[end+1:]
			continue
		case 3:
			start, _ := subTreeIdentify(xmlString, subTrees[original])
			rand.Seed(time.Now().UnixNano())
			addition := subTrees[rand.Intn(len(subTrees))]
			xmlString = xmlString[:start] + addition + xmlString[start:]
			continue
		default:
			continue
		}
	}
	return xmlString
}

func subTreeIdentify(xmlString string, subTree string) (int, int) {
	start := -1
	end := -1

	start = strings.Index(xmlString, subTree)
	end = start + len(subTree) - 1

	return start, end
}


// Implementation of leaf mutation algorithm
// TODO: finish this after finishing position mutation algorithm.

func (m *positionMutator) leafMutation(ml *parser.MyListener) {
	//attr := ml.Attr
	//contents := ml.Contents
	//tags := ml.TagNames
	//terminals := ml.Terminals
	// First, decide which type of leaf we want to operate on: 0-attr; 1-content; 2-tag name.
	rand.Seed(time.Now().UnixNano())
	choice := rand.Intn(3)
	// for now, we only consider the replacement
	switch choice {
	case 0:
		rand.Seed(time.Now().UnixNano())
		// TODO: do something.
	}

}

/*
	Below is the core logic of position mutation
	====================================================================================================================================================
 */

const PreProcessTime = 10 // This constant is used to define how many times should we mutate to gather results for statistical analysis before doing the actual fuzzing.
const TickerTime = 60 // This constant defines how long should we wait between two statistical analysis.
const MultiGen = 10 // This constant defines how many mutated files should we generate from one single initial seed.
const InitialSeedsPath = "../../seeds/initial" // This is the relative path where the initial seeds are stored.
const PhaseTwoSeedsPath = "../../seeds/phaseTwo" // This is the relative path where the seeds for phaseTwo are stored.
const SignatureReference = "<ds:ReferenceURI=" // This is used by extractProtected() to identify the URI of the protected content.

type statisticalTable struct {

}

type statisticalResults struct {

}

type position struct {
	depth, width   int
	insertionPoint int
}

type relativePosition struct {

}

// This type is used to store the result from a hot run

type hotResult struct {

}

func (m *positionMutator) positionMutation() error {
	// Pre-process to generate the statistical table
	initialSeeds := fetchSeeds("initial")
	times := 0
	for _, seed := range initialSeeds {
		for times < PreProcessTime {
			if m.mutationPhase1(seed, MultiGen) {
				m.mutationPhase2(fetchSeeds("phaseTwo"))
			} else {
				continue
			}
			times++
		}
	}

	// Set up the ticker & do statistical analysis periodically
	ticker := time.NewTicker(TickerTime)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <- done:
				return
			case <- ticker.C:
				table := m.readTable()
				statResults := m.analyzeTable(table)
				m.writeAnalysis(statResults)
				m.scheduleSeeds(statResults)
			}
		}
	}()

	// The actual fuzzing stage
	seed := m.readNextSeed()
	for seed != "" {
		if m.mutationPhase1(seed, MultiGen) {
			m.mutationPhase2(fetchSeeds("phaseTwo"))
		} else {
			continue
		}
		seed = m.readNextSeed()
	}

	return nil
}

// This function handles the position mutation part

func (m *positionMutator) mutationPhase1(seed string, fileNum int) bool {
	// Get the position map from modified ANTLR4 parser
	mutationParser := parser.NewAntlrParser("positionMutator")
	mutationParser.Parse(seed)
	m.positionMap = m.identifyPositions(mutationParser.Listener)

	// Extract protected information
	// TODO: Need modification to the function
	protected := m.extractProtected(mutationParser.Listener.SubTrees)

	// Generate payload from the extracted information
	payload := m.buildPayload(protected)
	// TODO: Need to modify the "positionMutate" function
	for i := 0; i < fileNum; i++ {
		mutatedSeed, scP, pP := m.positionMutate(protected, payload, mutationParser.Listener)
		result := m.validityCheck(mutatedSeed)
		relativeP := m.calculateRelative(scP, pP)
		m.writeTable(relativeP, result, "phaseOne")
		m.writeMutatedSeed(mutatedSeed, "phaseOne")
	}



	return false
}

// This function handles the random mutation part

func (m *positionMutator) mutationPhase2(seeds []string) error {

	for _, seed := range seeds {
		mutatedSeed := m.randomMutate(seed)
		validityResult := m.validityCheck(mutatedSeed)
		hotR := m.deliverToTarget(seed, mutatedSeed)
		m.writeTable(hotR, validityResult, "phaseTwo")
		m.writeMutatedSeed(mutatedSeed, "phaseTwo")
	}

	return nil
}

/*
	fetchSeeds() should return only the names in "initial" phase to be compatible with parser.Parse()
 */

func fetchSeeds(phase string) []string {
	var seeds []string

	switch phase {
	case "initial":
		helpers.ReadFileFromDir(InitialSeedsPath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				fmt.Println("Inside fetchSeeds(initial): ", err)
				return err
			}
			seeds = append(seeds, path)
			return nil
		})
	case "phaseTwo":
		helpers.ReadFileFromDir(PhaseTwoSeedsPath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				fmt.Println("Inside fetchSeeds(phaseTwo): ", err)
				return err
			}
			content, _ := os.ReadFile(path)
			seeds = append(seeds, string(content))
			return nil
		})
	}
	// This is due to an unknown issue that cause the generated slice always start with an empty file name
	return seeds[1:]
}

func (m *positionMutator) readTable() *statisticalTable {

	return new(statisticalTable)
}

func (m *positionMutator) analyzeTable(table *statisticalTable) *statisticalResults {

	return new(statisticalResults)
}

func (m *positionMutator) writeAnalysis(results *statisticalResults) {

}

func (m *positionMutator) scheduleSeeds(schedule *statisticalResults) {

}

func (m *positionMutator) readNextSeed() string {

	return ""
}

/*
	This function works as follows:
		1. find the sub-tree contains <ds:Reference> tag ✅
		2. extract URI value ✅
		3. use the value extracted to find the sub-tree in which contains it and return the sub-tree ✅
 */

func (m *positionMutator) extractProtected(subTrees []string) string {
	var protected string

	// Step 1
	signatureRefTree, _ := regexp.Compile(SignatureReference)
	for i, v := range subTrees {
		// this assumes the regular expression provided by the function caller can uniquely identify the protected part.
		// also, it makes sense to stop at the first match from the subTrees array, because antlr process the doc in
		// a DFS manner, so the first matched string will be the smallest subtree that contains the protected part.
		if signatureRefTree.MatchString(v) {
			protected = subTrees[i]
			break
		}
	}

	// Step 2
	// TODO: now this extraction mechanism assumes too much of the target file, need to relax the assumption in the next version.
	startIndex := 18 // the length of '<ds:ReferenceURI="'
	endIndex := -1
	for i, c := range protected {
		if string(c) == ">" {
			endIndex = i - 2
			break
		}
	}

	// Step 3
	// TODO: now this part of code assumes the protected content always has an attribute in the form of 'ID="protected"', need to relax this assumption
	tmp := "ID=\"" + protected[startIndex:endIndex+1]
	protectedTree, _ := regexp.Compile(tmp)
	for i, v := range subTrees {
		if protectedTree.MatchString(v) {
			protected = subTrees[i]
			fmt.Println("Found one !!!!!!!!!")
			break
		}
	}

	return protected
}

// This function is problem-specific, it depends on what vulnerability the user is targeting.

func (m *positionMutator) buildPayload(protected string) string {
	var payload string

	// For XSW attack - change the id and the content value of the protected part.
	newId := "id=\"attack\""
	newContent := "payload"
	// generate payload
	r1, _ := regexp.Compile("id=\"([a-z]+[0-9])\"")
	index := r1.FindStringSubmatchIndex(protected)
	payload = protected[:index[0]] + newId + protected[index[1]:]
	// replace original content
	r2, _ := regexp.Compile(">.<")
	contentIndex := r2.FindStringSubmatchIndex(payload)
	payload = payload[:contentIndex[0]+1] + newContent + payload[contentIndex[1]-1:]

	return payload
}

/*
	The algorithm is designed according to the behavior of Antlr 4.
	The algorithm is:
		1. see "<....>" : 1) depth++; 2) if depth not seen -> mark x:0; if depth seen -> mark depth:++width
		2. see "<.../...>": 1) depth--; 2) mark depth:++width
		3. see "<..../>": 1) mark depth:++width
 */

func (m *positionMutator) identifyPositions(ml *parser.MyListener) []position {
	var memory []string
	var positions []position
	positionTracker := make(map[int]int)
	var width int


	depth := -1
	terminals := ml.Terminals
	for i, v := range terminals {

		switch v {
		case "<":
			fallthrough
		case "/":
			memory = append(memory, v)
		case ">":
			if strings.Join(memory, "") == "<" {
				depth++
				// check if we've already visited this depth before
				if _, ok := positionTracker[depth]; ok {
					width = positionTracker[depth] + 1
					positionTracker[depth]++
				} else {
					width = 0
					positionTracker[depth] = 0
				}
				positions = append(positions, position{
					depth:          depth,
					width:          width,
					insertionPoint: i,
				})
				memory = []string{""}
			} else if strings.Join(memory, "") == "</" {
				depth--
				if depth < 0  { break }

				positions = append(positions, position{
					depth:          depth,
					width:          positionTracker[depth] + 1,
					insertionPoint: i,
				})
				positionTracker[depth]++
				memory = []string{""}
			}
		case "/>":
			positions = append(positions, position{
				depth:          depth,
				width:          positionTracker[depth] + 1,
				insertionPoint: i,
			})
			positionTracker[depth]++
			memory = []string{""}
		}
	}

	return positions
}

// A scoreboard is a map between the relative position and the potential ability to find more vulnerabilities

func buildScoreBoard(positions []position) {

}

func (m *positionMutator) positionMutate(protected string, payload string, ml *parser.MyListener) (string, position, position) {
	terminals := ml.Terminals
	var iProtected, iPayload int
	// TODO: after a scoreboard is available, the insertion should be carried out according to the score board
	rand.Seed(time.Now().UnixNano())
	for {
		iProtected = rand.Intn(len(m.positionMap))
		iPayload = rand.Intn(len(m.positionMap))
		if iProtected != iPayload {
			break
		}
	}
	x := m.positionMap[iProtected].insertionPoint
	y := m.positionMap[iPayload].insertionPoint
	if x < y {
		return strings.Join(terminals[:x+1], "") + protected + strings.Join(terminals[x+1:y+1], "") + payload + strings.Join(terminals[y+1:], ""), position{}, position{}
	} else {
		return strings.Join(terminals[:y+1], "") + payload + strings.Join(terminals[y+1:x+1], "") + protected + strings.Join(terminals[x+1:], ""), position{}, position{}
	}
}

func (m *positionMutator) validityCheck(mutatedSeed string) bool {

	return false
}

func (m *positionMutator) calculateRelative(scP position, pP position) relativePosition {

	return relativePosition{}
}

func (m *positionMutator) writeTable(relativeP interface{}, result interface{}, phase string) {


}

func (m *positionMutator) writeMutatedSeed(mutatedSeed string, phase string) {

}

func (m *positionMutator) randomMutate(seed string) string {

	return ""
}

func (m *positionMutator) deliverToTarget(originalSeed string, mutatedSeed string) hotResult {

	return hotResult{}
}

/*
	This is the end of position mutation logic
	====================================================================================================================================================
 */