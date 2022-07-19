package mutationPool

import (
	"fmt"
	"xmlMutator/pkg/helpers"
)

type mutationPool struct {
	name string
	location string
	// TODO: for now, use "" to indicate default algo
	algo string
	mutatedSeeds []string
}

func Init(location, name, algo string) *mutationPool {
	myMutationPool := &mutationPool{
		name:         name,
		location:     location,
		algo:         algo,
		mutatedSeeds: nil,
	}

	return myMutationPool
}

// This function will only add seed to memory.

func (mp *mutationPool) AddSeeds(mutatedSeed string) {
	mp.mutatedSeeds = append(mp.mutatedSeeds, mutatedSeed)
}

// This function will only add the seed to local storage.

func (mp *mutationPool) AddSeedsLocal(mutatedSeed string) {
	helpers.WriteStringToFile(mutatedSeed, mp.location+mp.name)
}

// TODO: when more sorting algorithms added, need to add a switch here

func (mp *mutationPool) SortSeeds(algo string) {
	defaultSorting()
}

func defaultSorting() {
	fmt.Println("Running default sorting algorithm...")
}

// return specified number of seeds

func (mp *mutationPool) FetchSeeds(number int) []string {
	if number > len(mp.mutatedSeeds) {
		return mp.mutatedSeeds
	}
	return mp.mutatedSeeds[:number]
}