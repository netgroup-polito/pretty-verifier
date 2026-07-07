package main

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

var comparators = []string{"<", ">", "<=", ">=", "==", "!="}
var varRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func randomizeComparator(s string) string {
	for _, op := range comparators {
		if strings.Contains(s, op) {
			alt := comparators[rand.Intn(len(comparators))]
			for alt == op {
				alt = comparators[rand.Intn(len(comparators))]
			}
			return strings.Replace(s, op, alt, 1)
		}
	}
	/*if varRegex.MatchString(s) {
		return "!" + s
	}*/
	return s
}

var comparatorRegex = regexp.MustCompile(`(==|!=|<=|>=|<|>)\s*(-?[0-9]+)`)

func shiftRHS(s string) (string, int) {
	if matches := comparatorRegex.FindStringSubmatchIndex(s); matches != nil {
		amount := rand.Intn(201) - 100
		start, end := matches[4], matches[5]
		origNumStr := s[start:end]
		num, _ := strconv.Atoi(origNumStr)
		newNum := num + amount
		modified := s[:start] + strconv.Itoa(newNum) + s[end:]
		return modified, amount
	}
	return s, 0

}
