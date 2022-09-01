package mutator

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
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
	Name         string `json:"name"`
	Algo         string `json:"algo"`
	MaxIteration int    `json:"max_iteration"`
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
	name            string
	config          *MutationConfig
	mp              *mutationPool
	positionMap     []position
	scoreBoardReady bool
	board           scoreBoard
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
				name:   name,
				config: &config.Configs[i],
				mp:     new(mutationPool),
				board:  make(scoreBoard),
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
		original := rand.Intn(len(subTrees) - 1)
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

const PreProcessTime = 10                      // This constant is used to define how many times should we mutate to gather results for statistical analysis before doing the actual fuzzing.
const TickerTime = 60                          // This constant defines how long should we wait between two statistical analysis.
const MultiGen = 10                            // This constant defines how many mutated files should we generate from one single initial seed.
const InitialSeedsDir = "../../seeds/initial"  // This is the relative path where the initial seeds are stored.
const SignatureReference = "<ds:ReferenceURI=" // This is used by extractProtected() to identify the URI of the protected content.
const DsTag = "<ds:Signature"                  // This is used by extractProtected() to identify the ds:Signature tag.
const PayloadId = "ID=\"attack\""              // This is used by buildPayload() to uniquely identify our self-built payload.
const SamlSignPath = "/Users/lhymm/SAML_Fuzzer/preFilterTools/samlSign"
const XmlSecToolPath = "/Users/lhymm/SAML_Fuzzer/preFilterTools/xmlsectool"
const PhaseOneDir = "../../seeds/phaseOne"
const PhaseTwoDir = "../../seeds/phaseTwo"
const LargeIntNumber = 4294967295

type metrics struct {
	pass int
	fail int
}

type scoreBoard map[relativePosition]metrics

func (b scoreBoard) newBoard() scoreBoard {
	return make(map[relativePosition]metrics)
}

type statisticalResults map[relativePosition]float32

type position struct {
	depth, width   int
	location       int // 1 -> within the protected part; 0 -> outside
	insertionPoint int
}

type relativePosition struct {
	x int
	y int
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
			case <-done:
				return
			case <-ticker.C:
				board := m.readScoreBoard()
				statResults := m.analyzeScoreBoard(board)
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
	// extract protected information
	fullProtected, protected, protectedID := m.extractProtected(mutationParser.Listener.SubTrees)
	m.positionMap = m.identifyPositions(mutationParser.Listener, fullProtected)

	// Generate payload from the extracted information
	payload := m.buildPayload(protected, protectedID)
	for i := 0; i < fileNum; i++ {
		mutatedSeed, payloadPosition, protectedPosition := m.positionMutate(payload, fullProtected, mutationParser.Listener)
		seedPath := m.writeMutatedSeed(mutatedSeed, "phaseOne")
		result := m.validityCheck(seedPath, 0)
		// TODO: during stage 2 code-sprint, change the input to the position of protected part
		relativeP := m.calculateRelative(payloadPosition, protectedPosition)
		m.writeScoreBoard(relativeP, result, "phaseOne")
	}

	return false
}

// This function handles the random mutation part

func (m *positionMutator) mutationPhase2(seeds []string) error {

	for _, seed := range seeds {
		mutatedSeed := m.randomMutate(seed)
		validityResult := m.validityCheck(mutatedSeed, 0)
		relativeP := m.deliverToTarget(seed, mutatedSeed)
		m.writeScoreBoard(relativeP, validityResult, "phaseTwo")
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
		helpers.ReadFileFromDir(InitialSeedsDir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				fmt.Println("Inside fetchSeeds(initial): ", err)
				return err
			}
			seeds = append(seeds, path)
			return nil
		})
	case "phaseTwo":
		// The reason to use "PhaseOneDir" is that the seeds should be used in phase 2 are generated by phase 1.
		helpers.ReadFileFromDir(PhaseOneDir, func(path string, info fs.FileInfo, err error) error {
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

// TODO: change the impl after database is used
func (m *positionMutator) readScoreBoard() scoreBoard {

	return m.board
}

// TODO: it should return a ordered list of relative positions
func (m *positionMutator) analyzeScoreBoard(board scoreBoard) statisticalResults {
	result := make(statisticalResults)
	for k, v := range board {
		passRate := float32(v.pass) / float32(v.pass+v.fail)
		result[k] = passRate
	}

	return result
}

// TODO: consider whether this function is actually needed or not
func (m *positionMutator) writeAnalysis(results statisticalResults) {

}

// TODO: this function should be based-on MPT theory
func (m *positionMutator) scheduleSeeds(schedule statisticalResults) {

}

// TODO: this function should be based-on MPT theory
func (m *positionMutator) readNextSeed() string {

	return ""
}

/*
	This function works as follows:
		1. find the sub-tree contains <ds:Reference> tag ✅
		2. extract URI value ✅
		3. use the value extracted to find the subtree in which contains it ✅
		4. exclude the entire <ds: Signature /> tag
*/

func (m *positionMutator) extractProtected(subTrees []string) (string, string, string) {
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
	startIndex := 19 // the length of '<ds:ReferenceURI="#'
	endIndex := -1
	for i, c := range protected {
		if string(c) == ">" {
			endIndex = i - 2
			break
		}
	}

	// Step 3
	// TODO: now this part of code assumes the protected content always has an attribute in the form of 'ID="protected"', need to relax this assumption
	protectedID := "ID=\"" + protected[startIndex:endIndex+1] + "\""
	protectedTree, _ := regexp.Compile(protectedID)
	// we need to return the first found result, due to the DFS search of Antlr4
	// the assumption here is the ds:signature element will use "#" + ref_id, so the smallest subtree contains a ref_id will be the protected part
	for i, v := range subTrees {
		if protectedTree.MatchString(v) {
			protected = subTrees[i]
			break
		}
	}

	// Additional step -> return the protected part before pruning
	fullProtected := protected

	// Step 4
	// TODO: not sure if it is necessary to exclude the ds:signature element
	signatureTree, _ := regexp.Compile(DsTag)
	for i, v := range subTrees {
		if signatureTree.MatchString(v) {
			start := strings.Index(protected, subTrees[i])
			end := start + len(subTrees[i])
			protected = protected[:start] + protected[end:]
			break
		}
	}

	return fullProtected, protected, protectedID
}

/*
	This function works as follows:
		1. change the ID portion from the protected code to a pre-defined value ✅
		2. return the generated ID-changed payload ✅
*/

func (m *positionMutator) buildPayload(protected string, protectedID string) string {
	var payload string

	newId := PayloadId
	// generate payload
	r1, _ := regexp.Compile(protectedID)
	index := r1.FindStringSubmatchIndex(protected)
	fmt.Println("The index is: ", index)
	fmt.Println("The length of protected is: ", len(protected))
	payload = protected[:index[0]] + newId + protected[index[1]:]

	return payload
}

/*
	The algorithm is designed according to the behavior of Antlr 4.
	The algorithm is:
		1. see "<....>" : 1) depth++; 2) if depth not seen -> mark x:0; if depth seen -> mark depth:++width
		2. see "<.../...>": 1) depth--; 2) mark depth:++width
		3. see "<..../>": 1) mark depth:++width
	Notice: current implementation exclude the protected part for position identification,
			this is because we assume any change within the protected part would invalidate the signature,
			if we want to also fuzz the possibility that changes within the protected part can also pass the check,
			then this function will need a re-write
*/

func (m *positionMutator) identifyPositions(ml *parser.MyListener, fullProtected string) []position {
	var memory []string
	var positions []position
	positionTracker := make(map[int]int)
	var width int

	depth := -1
	terminals := strings.Join(ml.Terminals, "")

	start := strings.Index(terminals, fullProtected)
	end := start + len(fullProtected) - 1
	location := -1
	/*	// identify the index of the protected part, because it should be untouchable
		start := strings.Index(terminals, protected)
		end := start + len(protected)
		fmt.Println("Start and end are: ", start, end)*/
	var seenElement []string
	for i, v := range terminals {
		// the two ifs bellow is designed to deal with the issue mentioned in the "notice" above
		/*if i >= start && i < end {
			continue
		}

		if i == end {
			positions = append(positions, position{
				depth:          depth,
				width:          positionTracker[depth] + 1,
				insertionPoint: i,
			})
			continue
		}*/

		seenElement = append(seenElement, string(v))
		switch string(v) {
		case "<":
			memory = append(memory, string(v))
		case "/":
			if seenElement[i-1] == "<" {
				memory = append(memory, string(v))
			}
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

				if i > start && i < end {
					location = 1
				} else {
					location = 0
				}

				positions = append(positions, position{
					depth:          depth,
					width:          width,
					location:       location,
					insertionPoint: i,
				})
				memory = []string{""}
			} else if strings.Join(memory, "") == "</" {
				depth--
				if depth < 0 {
					break
				}

				if i > start && i < end {
					location = 1
				} else {
					location = 0
				}

				positions = append(positions, position{
					depth:          depth,
					width:          positionTracker[depth] + 1,
					location:       location,
					insertionPoint: i,
				})
				positionTracker[depth]++
				memory = []string{""}
			}
		case "/>":

			if i > start && i < end {
				location = 1
			} else {
				location = 0
			}

			positions = append(positions, position{
				depth:          depth,
				width:          positionTracker[depth] + 1,
				location:       location,
				insertionPoint: i,
			})
			positionTracker[depth]++
			memory = []string{""}
		}
	}

	return positions
}

/*
	This function works as follows:
		0. to prepare the file for mutation, it first identifies the protected part from the file
		1. it then checks if there is an available score board to use ✅
		2. if no score board ready, randomly choose positions from the position map and insert ✅
		3. if score board is ready, choose insertion point using some strategy
		4. after the insertion, it deletes the original protected part from the file

	TODO:
		For the first stage of implementation, we'll keep the protected part unmoved and only inject the payload randomly.
		During the next code sprint, we'll randomly insert payload and protected part
*/

func (m *positionMutator) positionMutate(payload string, protected string, ml *parser.MyListener) (string, position, position) {
	// Step 0
	result := ""
	var payloadPosition, protectedPosition position
	terminals := strings.Join(ml.Terminals, "")

	// Step 1-3
	// TODO: after a scoreboard is available, the insertion should be carried out according to the score board
	result, payloadPosition, protectedPosition = m.insert(terminals, payload, protected)

	// Step 4
	return result, payloadPosition, protectedPosition

}

/*
	This function works as follows:
		1. analyze the score board
		2. pick the most desirable relative position
		3. go through the position map, find all
*/

func (m *positionMutator) insert(terminals string, payload string, protected string) (string, position, position) {
	result := ""
	var p relativePosition
	if m.scoreBoardReady {
		results := m.analyzeScoreBoard(m.board)
		// TODO: really ugly logic below
		max := float32(-1.0)
		// find the relative position with the highest pass-rate
		for k, v := range results {
			if max < v {
				max = v
				p = k
			}
		}
	} else {
		p = relativePosition{
			x: LargeIntNumber,
			y: LargeIntNumber,
		}
	}
	// insert according to the relative position
	rand.Seed(time.Now().UnixNano())
	iPayload := rand.Intn(len(m.positionMap))
	if m.positionMap[iPayload].location == 1 {
		// If the index is within the protected part, don't move the protected part
		y := m.positionMap[iPayload].insertionPoint
		result = terminals[:y+1] + payload + terminals[y+1:]
		return result, m.positionMap[iPayload], position{-1, -1, -1, -1}
	} else {
		// 0. index the original protected part
		start := strings.Index(terminals, protected)
		end := start + len(protected) - 1
		var rx, ry, x, y, iProtected int
		var found bool
		for loop := 0; loop < 10; loop++ {
			// If the index is outside the protected part:
			// 1. choose a position randomly
			iProtected = rand.Intn(len(m.positionMap))
			// 2. check if the relative position is ok
			rx = m.positionMap[iPayload].depth - m.positionMap[iProtected].depth
			ry = m.positionMap[iPayload].width - m.positionMap[iProtected].width
			if rx <= p.x && ry <= p.y {
				x = m.positionMap[iPayload].insertionPoint
				y = m.positionMap[iProtected].insertionPoint
				if x <= y {
					result = terminals[:x+1] + payload + terminals[x+1:y+1] + protected + terminals[y+1:]
				} else {
					result = terminals[:y+1] + protected + terminals[y+1:x+1] + payload + terminals[x+1:]
				}
				// to delete the original protected part, we need to know which part got injected before the original protected part
				found = true
				break
			}
			// if not ok, continue looping
		}
		// if we couldn't find suitable positions through looping, we pick randomly
		if !found {
			iProtected = rand.Intn(len(m.positionMap))
			x = m.positionMap[iPayload].insertionPoint
			y = m.positionMap[iProtected].insertionPoint
		}

		if x <= start && y <= start {
			start = start + len(payload) + len(protected)
			end = end + len(payload) + len(protected)
		} else if x <= start {
			start = start + len(payload)
			end = end + len(payload)
		} else if y <= start {
			start = start + len(protected)
			end = end + len(protected)
		}

		result = result[:start] + result[end+1:]
		return result, m.positionMap[iPayload], m.positionMap[iProtected]
	}
}

func depthDown(protected string) string {
	return "<myWrapper>" + protected + "</myWrapper>"
}

/*
	This function works as follows:
		1. it first sends the seed to an external program ✅
		2. it then collects the results from that program ✅
		3. finally it will return a boolean value to indicate the validity of the seed

	Notice:
		The external program used below is "samlsign", the usage can be found at here:
		https://shibboleth.atlassian.net/wiki/spaces/SP3/pages/2065335509/samlsign#Signing

		And also "xmlsectool", which is a stricter tool than samlsign.

	mutatedSeed - represents the path to that seed
	strictLevel - represents how strict the validity check should be

	TODO: somewhere during the following code sprints, we should also store the error message generated from each mutated seed,
          so that we can classify seeds and calculate metrics more easier.
*/

func (m *positionMutator) validityCheck(mutatedSeed string, strictLevel int) bool {

	switch strictLevel {
	case 0:
		name := SamlSignPath + "/samlsign" // the absolute path to the executable
		cert := SamlSignPath + "/cert.pem" // the absolute path to the certificate
		cmd := exec.Command(name, "-c", cert, "-f", mutatedSeed)
		_, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("The error from samlsign is: ", err)
			return false
		}
	case 1:
		name := XmlSecToolPath + "/xmlsectool.sh"
		cert := XmlSecToolPath + "/cert.pem"
		outFile := XmlSecToolPath + "/result"
		cmd := exec.Command(name, "--verifySignature", "--inFile", mutatedSeed, "--outFile", outFile, "--certificate", cert, "--allowAllDigests")
		_, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("The error from xmlsectool is: ", err)
			return false
		}
	default:
		fmt.Println("Please use a valid strict level!")
		return false
	}

	return true
}

/*
	This func will return the relative position between the payload and the original signed element.
*/

func (m *positionMutator) calculateRelative(payload position, protected position) relativePosition {

	return relativePosition{payload.depth - protected.depth, payload.width - protected.width}
}

/*
	This function should work as follows:
		1. it first checks if there is an existing score board
		2. if not, first create an empty one, change m.scoreBoardReady to true
		3. then, write relevant information into it
		4. if the writing process failed, change m.scoreBoardReady to false
	TODO: Need to change the read/write operations to MySQL database !!! (right now everything is in memory)
	TODO: Need to address the code-reuse problem within this function
*/

func (m *positionMutator) writeScoreBoard(relativeP relativePosition, result bool, phase string) {
	if !m.scoreBoardReady {
		// create and write new score board
		board := make(scoreBoard)
		//board = board.newBoard()
		if result {
			board[relativeP] = metrics{
				pass: 1,
				fail: 0,
			}
		} else {
			board[relativeP] = metrics{
				pass: 0,
				fail: 1,
			}
		}
		m.board = board
		m.scoreBoardReady = true
		fmt.Println("The newly created score board is: ", m.board)
	} else {
		// add to existing score board
		v, ok := m.board[relativeP]
		if !ok {
			if result {
				m.board[relativeP] = metrics{
					pass: 1,
					fail: 0,
				}
			} else {
				m.board[relativeP] = metrics{
					pass: 0,
					fail: 1,
				}
			}
		} else {
			if result {
				m.board[relativeP] = metrics{
					pass: v.pass + 1,
					fail: v.fail,
				}
			} else {
				m.board[relativeP] = metrics{
					pass: v.pass,
					fail: v.fail + 1,
				}
			}
		}
		fmt.Println("The existing score board is: ", m.board)
	}
}

/*
	This function should work as follows:
		1. based-on the "phase" parameter, to choose a folder to write to
		2. name the file using a unix timestamp in milliseconds

	TODO: step 2 should be changed to use something that is descriptive of the file to name that file
*/

func (m *positionMutator) writeMutatedSeed(mutatedSeed string, phase string) string {

	path := ""

	switch phase {
	case "phaseOne":
		path = PhaseOneDir + "/" + phase + time.Now().GoString() + ".xml"
		helpers.WriteStringToFile(mutatedSeed, path)
	case "phaseTwo":
		path = PhaseTwoDir + "/" + phase + time.Now().GoString() + ".xml"
		helpers.WriteStringToFile(mutatedSeed, path)
	}
	return path
}

// TODO: consider whether this function should be implemented by ourself, or simply using AFL++ is enough
func (m *positionMutator) randomMutate(seed string) string {

	return seed
}

func (m *positionMutator) deliverToTarget(originalSeed string, mutatedSeed string) relativePosition {

	return relativePosition{}
}

/*
	This is the end of position mutation logic
	====================================================================================================================================================
*/
