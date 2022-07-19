package leaf_mutator

import (
	"fmt"
	"strings"
	"testing"
)

func TestFind(t *testing.T) {
	case1 := []string{"note", "name", "to"}
	v1 := "note"
	expect1 := true
	case2 := []string{"from", "xml"}
	v2 := "signature"
	expect2 := false
	case3 := []string{""}
	v3 := "digital"
	expect3 := false

	result1 := Find(v1, case1)
	result2 := Find(v2, case2)
	result3 := Find(v3, case3)

	if result1 != expect1 {
		t.Fatalf("The string slice is: %v, value is %s\nExpected result is \"true\", got %v", case1, v1, result1)
	}
	if result2 != expect2 {
		t.Fatalf("The string slice is: %v, value is %s\nExpected result is \"false\", got %v", case2, v2, result2)
	}
	if result3 != expect3 {
		t.Fatalf("The string slice is: %v, value is %s\nExpected result is \"false\", got %v", case2, v2, result2)
	}
}

func TestDoReplace(t *testing.T) {
	i1, j1 := 0, 3
	expect1 := "v4p2p3p4"
	i2, j2 := 1, 2
	expect2 := "v4v3p3p4"
	i3, j3 := 0, 0
	expect3 := "v1v3p3p4"
	slice1 := []string{"p1", "p2", "p3", "p4"}
	slice2 := []string{"v1", "v2", "v3", "v4"}

	DoReplace(i1, j1, slice1, slice2)
	if result := strings.Join(slice1, ""); result != expect1 {
		t.Fatalf("i1 is %d, j1 is %d, slice1 is %v, slice2 is %v\nExpect %s, got %s", i1, j1, slice1, slice2, expect1, result)
	}
	DoReplace(i2, j2, slice1, slice2)
	if result := strings.Join(slice1, ""); result != expect2 {
		t.Fatalf("i2 is %d, j2 is %d, slice1 is %v, slice2 is %v\nExpect %s, got %s", i2, j2, slice1, slice2, expect2, result)
	}
	DoReplace(i3, j3, slice1, slice2)
	if result := strings.Join(slice1, ""); result != expect3 {
		t.Fatalf("i3 is %d, j3 is %d, slice1 is %v, slice2 is %v\nExpect %s, got %s", i3, j3, slice1, slice2, expect3, result)
	}

}

func TestLeafMutationStrategy(t *testing.T) {
	mutateMask, elePick := LeafMutationStrategy(10)
	fmt.Printf("Mutation mask is: %v\nElement pick is: %v\n", mutateMask, elePick)
}