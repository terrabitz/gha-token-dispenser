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

type GitHubClaims struct {
	Jti                  string `json:"jti"`
	Sub                  string `json:"sub"`
	Environment          string `json:"environment"`
	Aud                  string `json:"aud"`
	Ref                  string `json:"ref"`
	Sha                  string `json:"sha"`
	Repository           string `json:"repository"`
	RepositoryOwner      string `json:"repository_owner"`
	ActorID              string `json:"actor_id"`
	RepositoryVisibility string `json:"repository_visibility"`
	RepositoryID         string `json:"repository_id"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RunID                string `json:"run_id"`
	RunNumber            string `json:"run_number"`
	RunAttempt           string `json:"run_attempt"`
	RunnerEnvironment    string `json:"runner_environment"`
	Actor                string `json:"actor"`
	Workflow             string `json:"workflow"`
	HeadRef              string `json:"head_ref"`
	BaseRef              string `json:"base_ref"`
	EventName            string `json:"event_name"`
	RefType              string `json:"ref_type"`
	JobWorkflowRef       string `json:"job_workflow_ref"`
	Iss                  string `json:"iss"`
}

type AuthorizationRule struct {
	Fields map[string][]Wildcard
}

func (claims GitHubClaims) MatchesAnyRule(rules []AuthorizationRule) (bool, error) {
	for _, rule := range rules {
		matches, err := claimMatchesRule(claims, rule)
		if err != nil {
			return false, fmt.Errorf("error matching rule: %w", err)
		}

		if matches {
			return true, nil
		}
	}

	return false, nil
}

func claimMatchesRule(claims GitHubClaims, rule AuthorizationRule) (bool, error) {
	for field, wildcards := range rule.Fields {
		claimValue, err := getStringValueByJSONTag(claims, field)
		if err != nil {
			return false, fmt.Errorf("couldn't match rules: %w", err)
		}

		if !Any(wildcards, func(wildcard Wildcard) bool {
			return wildcard.MatchString(claimValue)
		}) {
			return false, nil
		}
	}

	return true, nil
}
