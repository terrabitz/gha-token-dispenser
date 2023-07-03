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
	if err == nil {
		*a = multi
		return nil
	}

	var single string
	if err = value.Decode(&single); err != nil {
		return err
	}

	*a = []string{single}

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

func (claims GitHubClaims) GetMatchingRules(rules []AuthorizationRule) []AuthorizationRule {
	return Filter(rules, func(rule AuthorizationRule) bool {
		return claims.MatchesRule(rule)
	})
}

func (claims GitHubClaims) MatchesAnyRule(rules []AuthorizationRule) bool {
	return Any(rules, func(rule AuthorizationRule) bool {
		return claims.MatchesRule(rule)
	})
}

func (claims GitHubClaims) MatchesRule(rule AuthorizationRule) bool {
	return All(Keys(rule.Claims), func(field GitHubClaimName) bool {
		claimValue := claims.GetClaimValue(field)
		wildcards := rule.Claims[field]

		return Any(wildcards, func(wildcard Wildcard) bool {
			return wildcard.MatchString(claimValue)
		})
	})
}

func (claims GitHubClaims) GetClaimValue(field GitHubClaimName) string {
	claim, _ := getStringValueByJSONTag(claims, string(field))
	return claim
}

type AuthorizationRule struct {
	Claims      map[GitHubClaimName][]Wildcard
	Permissions PermissionSet
}

type GitHubClaimName string

func NewGitHubClaimsField(s string) (GitHubClaimName, error) {
	_, err := getStringValueByJSONTag(GitHubClaims{}, s)
	if err != nil {
		return GitHubClaimName(""), fmt.Errorf("invalid GitHub claim: '%s'", s)
	}

	return GitHubClaimName(s), nil
}

type PermissionSet map[string]GitHubAccessLevel

func (ps PermissionSet) GetAccessLevelString(permission string) *string {
	accessLevel, ok := ps[permission]
	if !ok {
		return nil
	}

	s := accessLevel.String()
	return &s
}

func MergePermissions(permSets []PermissionSet) PermissionSet {
	maxPerms := PermissionSet{}

	for _, permSet := range permSets {
		for permission, accessLevel := range permSet {
			if accessLevel.GreaterThan(maxPerms[permission]) {
				maxPerms[permission] = accessLevel
			}
		}
	}

	return maxPerms
}

// ENUM(
//
//	read=1
//	write=2
//	admin=3
//
// )
//
//go:generate go-enum --marshal
type GitHubAccessLevel int

func (gal GitHubAccessLevel) GreaterThan(other GitHubAccessLevel) bool {
	return gal > other
}
