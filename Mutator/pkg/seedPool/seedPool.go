package seedPool

import (
	"time"
	"xmlMutator/pkg/helpers"
)

/*
	This package will handle the management of a seedPool,
	It can fetch the seed, locally or remotely, into the memory,
	so there's no need to pre-download all the seeds,
	and it is also possible that we can run the mutator while crawling content
	from the Internet.
 */

type seed struct {
	// the name of the seed
	name string
	// the working path of the seed (it could be local or remote)
	path string
	// the content of the seed
	content string
}

type seedPool struct {
	// the name of the seed pool
	name string
	// the creation time of this pool
	time time.Time
	// all the fetched seeds
	// TODO: this will need some pre-set limit to limit the total number of seeds stored in memory.
	seeds []seed
}

func Init(name string, mySeeds ...seed) *seedPool {
	newSP := new(seedPool)
	newSP.name = name
	newSP.time = time.Now()
	for _, mySeed := range mySeeds {
		newSP.seeds = append(newSP.seeds, mySeed)
	}
	return newSP
}

// FetchSeed() will fetch the content of a seed into the memory
// TODO: for now, we only consider the seeds that stored locally

func (sp *seedPool) FetchSeed(name string, path string) error {
	content, err := helpers.ReadFileToString(name, path)
	newSeed := seed{
		name:    name,
		path:    path,
		content: content,
	}
	sp.seeds = append(sp.seeds, newSeed)
	return err
}

/*
	AddSeed() will write a seed file into the specified path for future mutation use,
	but the seed won't be stored in memory unless FetchSeed is called.
TODO: for now, we only considered file stored locally.
 */

func (sp *seedPool) AddSeed(content string, name string, path string) bool {
	r := helpers.WriteStringToFile(content, path + name)
	return r
}

/*
	DeleteSeed() will delete the specified seed from memory,
	but won't delete the actual file, that is up to the caller to decide.
 */

func (sp *seedPool) DeleteSeed(name string) {
	for i, seed := range sp.seeds {
		if seed.name == name {
			sp.seeds = append(sp.seeds[:i], sp.seeds[i+1:]...)
			return
		}
	}
}