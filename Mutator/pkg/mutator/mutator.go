package mutator

import (
	"encoding/json"
	"fmt"
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

type mutator struct {
	name string
	config *MutationConfig
	mp *mutationPool
}

func Init(name string, configPath string, configName string) *mutator {
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
			return &mutator{
				name:  	name,
				config: &config.Configs[i],
				mp:     new(mutationPool),
			}
		}
	}

	fmt.Println("No configuration matched the given algorithm name, return nil.")

	return nil
}

func (m *mutator) Mutate(ml *parser.MyListener) {
	var s string
	switch m.config.Algo {
	case "tree":
		s = m.treeMutation(ml)
	case "leaf":
		//leafMutation()
	case "position":
		s = m.positionMutation(ml)
	default:
		s = m.positionMutation(ml)
	}

	// This part is to solve the issue of <Nameid="123">
	// TODO: should be replaced by an add seed function from package mutationPool
	for v, _ := range ml.Attr {
		s = helpers.XMLStringRefactor("", s, v)
	}
	helpers.WriteStringToFile(s, "./result.xml")
}

// Implementation of tree mutation algorithm

func (m *mutator) treeMutation(ml *parser.MyListener) string {
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

func (m *mutator) leafMutation(ml *parser.MyListener) {
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
	Implementation of position mutation algorithm
	The algorithm works in following steps:
		1) identify the protected part, in the case of xml signature, the signed element S ✅
		2) build a payload P according to pre-coded rules ✅
		3) fuzz the relative position of S and P
 */

func (m *mutator) positionMutation(ml *parser.MyListener) string {
	subTrees := ml.SubTrees
	protected := identifyProtected(subTrees, "id=\"a1\"")
	fmt.Println("Protected part is: ", protected)
	payload := buildPayload(protected)
	fmt.Println("Payload is: ", payload)

	// 1. find all feasible positions (the function will remove the original protected part first)
	positions := identifyPositions(ml)
	positions = positions[:len(positions)-1]
	// 2. build a scoreboard
	// TODO: finish this
	// 3. insert original protected part and payload into random positions
	s := insert(protected, payload, positions, ml)

	return s
}

func identifyProtected(subTrees []string, protected string) string {
	var s string

	r, _ := regexp.Compile(protected)
	for i, v := range subTrees {
		// this assumes the regular expression provided by the function caller can uniquely identify the protected part.
		// also, it makes sense to stop at the first match from the subTrees array, because antlr process the doc in
		// a DFS manner, so the first matched string will be the smallest subtree that contains the protected part.
		if r.MatchString(v) {
			s = subTrees[i]
			break
		}
	}

	return s
}

// This function is problem-specific, it depends on what vulnerability the user is targeting.

func buildPayload(protected string) string {
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

type position struct {
	depth, width   int
	insertionPoint int
}

/*
	The algorithm is designed according to the behavior of Antlr 4.
	The algorithm is:
		1. see "<....>" : 1) depth++; 2) if depth not seen -> mark x:0; if depth seen -> mark depth:++width
		2. see "<.../...>": 1) depth--; 2) mark depth:++width
		3. see "<..../>": 1) mark depth:++width
 */

func identifyPositions(ml *parser.MyListener) []position {
	var memory []string
	var positions []position
	positionTracker := make(map[int]int)
	var width int


	depth := -1
	fileSlice := ml.Terminals
	for i, v := range fileSlice {
		if v == "<" || v == "/" {
			memory = append(memory, v)
		} else if v == ">" {
			if strings.Join(memory, "") == "<" {
				depth++
				// check if we've already visited this depth before
				if _, ok := positionTracker[depth]; ok {
					width = positionTracker[depth]+1
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
				positions = append(positions, position{
					depth:          depth,
					width:          positionTracker[depth]+1,
					insertionPoint: i,
				})
				positionTracker[depth]++
				memory = []string{""}
			}
		} else if v == "/>" {
			positions = append(positions, position{
				depth:          depth,
				width:          positionTracker[depth]+1,
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

func insert(protected string, payload string, positions []position, ml *parser.MyListener) string {
	terminals := ml.Terminals
	var iProtected, iPayload int
	// TODO: after a scoreboard is available, the insertion should be carried out according to the score board
	rand.Seed(time.Now().UnixNano())
	for {
		iProtected = rand.Intn(len(positions))
		iPayload = rand.Intn(len(positions))
		if iProtected != iPayload {
			break
		}
	}
	x := positions[iProtected].insertionPoint
	y := positions[iPayload].insertionPoint
	if x < y {
		return strings.Join(terminals[:x+1], "") + protected + strings.Join(terminals[x+1:y+1], "") + payload + strings.Join(terminals[y+1:], "")
	} else {
		return strings.Join(terminals[:y+1], "") + payload + strings.Join(terminals[y+1:x+1], "") + protected + strings.Join(terminals[x+1:], "")
	}
}