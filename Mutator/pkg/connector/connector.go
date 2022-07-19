package connector

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
)

/*
	The connector package should also do some maintaining job,
	but for now, only the seed sending function is implemented.
 */

type connector struct {
	name string
	mutationPoolPath string
	alfppPath string
}

func Init(name, mutationPoolPath, aflppPath string) *connector {
	return &connector{
		name:             name,
		mutationPoolPath: mutationPoolPath,
		alfppPath:        aflppPath,
	}
}

// TODO: for now, Send() will send all the seeds in a mutation pool to AFL++

func (mc *connector) Send() {
	if err := copyGlob(mc.mutationPoolPath + "/*.xml", mc.alfppPath); err != nil {
		log.Fatal(err)
	}
}

func copyGlob(src string, destDir string) error {
	files, err := filepath.Glob(src)
	if err != nil {
		return err
	}
	for _, f := range files {
		fmt.Println(f)
		dest := filepath.Join(destDir, filepath.Base(f))
		if err := myCopy(f, dest); err != nil {
			return fmt.Errorf("cannot copy %q to %q", f, dest)
		}
	}

	return nil
}

func myCopy(src, dest string) error {
	cmd := exec.Command("cp", src, dest)
	return cmd.Run()
}