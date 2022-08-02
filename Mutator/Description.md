# Position Mutator - for XML
## The structure after a complete OOP refactor
![](pics/PositionMutatorOOP.png)
## Object Details
### seedPool ✅
1. Description:\
   This object will handle the storage of input seeds.\
   The seeds don't need to be downloaded into  local storage,\
   this SeedPool only needs a path to the seed in question,\
   then it will fetch the content automatically (if it's remote) and store them locally when required by the mutator.
2. Operations:
    1. ```func (sp *seedPool) AddSeed(name string, path string) error {}```
    2. ```func (sp *seedPool) DeleteSeed(name string) error {}```
    3. ```func (sp *seedPool) FetchSeed(name string) seed {}```
    4. ```func (sp *seedPool) Init() error {}```
3. Data structure:

```go
package description

import "time"

type seed struct {
	// the name of the seed
	name string
	// the path of the seed, locally or remotely
	path string
	// the content of the seed
	content string
}

type seedPool struct {
	// the name of this seed pool
	name string
	// the time at the creation of this pool
	time  time.Time
	// the collection of seeds
	seeds []seed
}
```
### antlrParser ✅
1. Description:\
   This object will parse an input seed into an AST, then extracted relevant information\
   from the AST according to the chosen mutation algorithm. The extracted information will\
   be stored in memory for mutator to use directly. This design choice make this fuzzer\
   memory-heavy instead of io-heavy.
2. Operations:
    1. ```func (ap *antlrParser) Parse() {}``` 
3. Data structure

```go
package description

import parser "xmlMutator/xmlGrammar"

type antlrParser struct {
   name     string
   listener *MyListener
}

type MyListener struct {
   *parser.BaseXMLParserListener
   strategy string
   Attr map[string][]string
}
```
### MParser ⌛️
1. Description:\
   This object will parse the outputs of the antlrParser to a suitable format for the\
   mutator to use according to the chosen mutation algorithm.
2. Operations:
    1. ```func (mp *mParser) Parse(algo string) error {}```
3. Data structure:
```go
package description

type mParsed struct {
	// ......
}

type mParser struct {
	name        string
	parsedFiles []mParsed
}
```
### Mutator
1. Description:\
   This object will handle the actual mutation process for an input according to\
   the chosen mutation algorithm.
2. Operations:
    1. ```func (m *mutator) Mutate(algo string) error {}```
    2. ```func (m *mutator) Config(myConfig MutationConfig) {}```
    3. ```func Init(name, configPath, configName string) *mutator```
3. Data structure:

```go
package description

import "time"

type Configs struct {
	Configs []MutationConfig
}

type MutationConfig struct {
   Name         string      `json:"name"`
   Type         string      `json:"type"` // the chosen mutation algorithm
   MaxIteration int         `json:"max_iteration"`
   // ......
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
   name         string
   config       *MutationConfig
   mp           *mutationPool
}
```
### MutationPool ✅
1. Description:\
   This object will handle the storage of the mutated seeds, and ranking the mutated seeds\
   according to specified ranking algorithm.
2. Operations:
    1. ```func (mp *mutatedPool) AddSeeds(mutatedFiles []mutated) error {}```
    2. ```func (mp *mutatedPool) SortSeeds(algo string) {}```
    3. ```func (mp *mutatedPool) FetchSeeds(number int) error {}```
3. Data structure:
```go
package description

type ranking struct {
	name string // the name of the chosen ranking algorithm
}

func (r *ranking) Rank() {
	
}

type mutationPool struct {
	name string
	algo map[string]ranking
	storageList []string // a list of stored mutated seeds
}
```
### Connector ✅
1. Description:\
   This object will handle the connection between the mutator and AFL++, it will fetch\
   some amount of seeds (configurable) from the mutated seed pool, and put them\
   into the 'input' folder of a running AFL++ instance.
2. Operations:
    1. ```func (c *connector) Connect() error {}```
    2. ```func (c *connector) Send() error {}```
3. Data structure:
```go
package description

type connector struct {
	name string
	mutatedPoolPath string
	aflppPath string
	amount int // the amount to be sent to the AFL++
}
```

### Current Testing
mutator.go -> mutationPhase1() -> writeSoreBoard()

### Need changing

Another thing to notice is, when doing mutation after we have a score board, we should not completely
ignore the seeds that couldn't pass the check, we should however, continue mutating on them and monitor
the results and record that results into the score board as a guide.

mutator.go -> positionMutate()