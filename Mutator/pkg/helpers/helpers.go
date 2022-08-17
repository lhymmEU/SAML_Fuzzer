package helpers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func WriteStringToFile(s string, path string) bool {
	f, err := os.Create(path)
	if err != nil {
		fmt.Printf("File creation failed: %s", err)
		return false
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	_, err2 := w.WriteString(s)
	if err2 != nil {
		fmt.Printf("Write to file failed: %s", err2)
		return false
	}
	w.Flush()

	return true
}

func AppendToFile(s string, path string) bool {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Printf("Open file %s failed: %s", s, err)
		return false
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	if _, err := w.WriteString(s); err != nil {
		fmt.Printf("Append write to file %s failed: %s", path, err)
		return false
	}
	defer w.Flush()

	return true
}

func ReadFileToSlice(f *os.File) []string {
	result := []string{""}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		result = append(result, scanner.Text())
	}

	return result
}

// TODO: add a general error handler function and replace all existing error handling code

func GenErrorHandler() {

}

/*
	This function need to handle the "<Nameid="123">" issue in terminals.txt.
	Steps:
		1. Go through the terminals slice.
		2. if the terminal
		3. Add a white space " " in front of the index.
*/

func TerminalsRefactor(terminals []string) []string {

	for i, v := range terminals {
		if v == "=" {
			terminals[i-1] = " " + terminals[i-1]
		}
	}

	return terminals
}

/*
	This function need to handle the "<Nameid="123">" issue in sub_trees.txt.
	Steps:
		1.
*/

func XMLStringRefactor(leftString string, rightString string, v string) string {
	index := strings.Index(rightString, v)
	if index == -1 {
		return rightString
	}
	leftString = rightString[:index] + " " + string(rightString[index])
	rightString = rightString[index+1:]
	return leftString + XMLStringRefactor(leftString, rightString, v)
}

func BuildXMLString(leaves []string) string {

	xmlString := strings.Join(leaves, "")

	return xmlString
}

func ParseAttributes(s string) []string {
	return strings.Split(s, "=")
}

func ReadFileToString(name string, path string) (string, error) {
	result, err := os.ReadFile(path + name)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func ReadFileFromDir(dirName string, walkFn filepath.WalkFunc) error {
	err := filepath.Walk(dirName, walkFn)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func WriteJsonToFile(path string, jsonStr []byte) {
	file, _ := os.OpenFile(path, os.O_CREATE, os.ModePerm)
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.Encode(jsonStr)
}
