package seedPool

import (
	"fmt"
	"testing"
)

func TestSeedPool_FetchSeed(t *testing.T) {
	myPool := Init("Mine")
	myPool.FetchSeed("input.xml", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/cmd/mutator/")
	fmt.Println(myPool.name, myPool.time, myPool.seeds)
}

func TestSeedPool_AddSeed(t *testing.T) {
	myPool := Init("Mine")
	myPool.AddSeed("<Test><element>b</element></Test>", "input2.xml", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/cmd/mutator/")
	myPool.AddSeed("<Again><element>c</element></Again>", "input3.xml", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/cmd/mutator/")
}

func TestSeedPool_DeleteSeed(t *testing.T) {
	myPool := Init("Mine")
	myPool.FetchSeed("input.xml", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/cmd/mutator/")
	myPool.FetchSeed("input2.xml", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/cmd/mutator/")
	myPool.FetchSeed("input3.xml", "/Users/lhymm/xmlsignaturefuzzing/xmlMutator/cmd/mutator/")
	fmt.Println("Before delete: ", myPool.name, myPool.time, myPool.seeds)
	myPool.DeleteSeed("input.xml")
	fmt.Println("After first delete: ", myPool.name, myPool.time, myPool.seeds)
	myPool.DeleteSeed("input2.xml")
	fmt.Println("After second delete: ", myPool.name, myPool.time, myPool.seeds)
	myPool.DeleteSeed("input3.xml")
	fmt.Println("After third delete: ", myPool.name, myPool.time, myPool.seeds)
	myPool.DeleteSeed("input4.xml")
	fmt.Println("After fourth delete: ", myPool.name, myPool.time, myPool.seeds)
}