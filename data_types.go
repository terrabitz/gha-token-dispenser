package main

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type SingleOrMulti []string

func (a *SingleOrMulti) UnmarshalYAML(value *yaml.Node) error {
	var multi []string
	err := value.Decode(&multi)
	if err != nil {
		var single string
		err := value.Decode(&single)
		if err != nil {
			return err
		}
		*a = []string{single}
	} else {
		*a = multi
	}
	return nil
}

type Repository struct {
	Name     string
	Owner    string
	FullName string
}

func ParseRepository(orgAndRepo string) (Repository, error) {
	parts := strings.Split(orgAndRepo, "/")
	if len(parts) != 2 {
		return Repository{}, fmt.Errorf("invalid format for repository '%s'; must use 'org/name' format", orgAndRepo)
	}

	return Repository{
		Owner:    parts[0],
		Name:     parts[1],
		FullName: orgAndRepo,
	}, nil
}

type Wildcard struct {
	*regexp.Regexp
}

func NewWildcard(s string) Wildcard {
	escaped := regexp.QuoteMeta(s)
	expanded := strings.Replace(escaped, "\\*", ".*", -1)
	anchored := fmt.Sprintf("^%s$", expanded)
	re, _ := regexp.Compile(anchored)

	return Wildcard{
		Regexp: re,
	}
}

func NewWildcards(ss ...string) []Wildcard {
	var wildcards []Wildcard
	for _, s := range ss {
		wildcards = append(wildcards, NewWildcard(s))
	}

	return wildcards
}
