package mutationPool

import (
	"fmt"
	"testing"
)

func TestInit(t *testing.T) {
	myPool := Init("./", "test1.xml", "")
	myPool.AddSeeds("Hi, I'm the first added seed!")
	myPool.AddSeeds("Hi, I'm the second added seed!")
	myPool.AddSeedsLocal("Hola, I'm a locally stored seed!")
	fmt.Println("myPool is: ", myPool)
}
