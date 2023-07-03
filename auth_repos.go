package main

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type MemRuleRepository struct{}

func (_ MemRuleRepository) GetRulesForRepo(_ context.Context, repo Repository) ([]AuthorizationRule, error) {
	rules := map[string][]AuthorizationRule{
		"terrabitz/goreleaser-test": {{
			Claims: map[GitHubClaimName][]Wildcard{
				"sub":              NewWildcards("repo:terrabitz/goreleaser-test:*"),
				"job_workflow_ref": NewWildcards("terrabitz/goreleaser-test/.github/workflows/send-oidc-token.yaml@*"),
			},
		}},
	}

	rule, ok := rules[repo.FullName]
	if !ok {
		return nil, fmt.Errorf("repo '%s' isn't defined in the map", repo.FullName)
	}

	return rule, nil
}

type FileRuleRepository struct {
	RepoRules map[string][]AuthorizationRule
}

type FileRuleRepositoryConfig struct {
	RepoRules map[string][]struct {
		Claims map[string]SingleOrMulti `yaml:"claims"`
	} `yaml:"repo_rules,inline"`
}

func NewFileRuleRepository(file string) (FileRuleRepository, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return FileRuleRepository{}, fmt.Errorf("couldn't read file '%s': %w", file, err)
	}

	var config FileRuleRepositoryConfig
	yaml.Unmarshal(b, &config)

	frr := FileRuleRepository{
		RepoRules: map[string][]AuthorizationRule{},
	}
	for repo, rules := range config.RepoRules {
		var authRules []AuthorizationRule
		for _, rule := range rules {
			claims := map[GitHubClaimName][]Wildcard{}
			for claim, values := range rule.Claims {
				var wildcards []Wildcard
				for _, value := range values {
					wildcards = append(wildcards, NewWildcard(value))
				}

				claimField, err := NewGitHubClaimsField(claim)
				if err != nil {
					return FileRuleRepository{}, err
				}

				claims[claimField] = wildcards
			}

			authRules = append(authRules, AuthorizationRule{
				Claims: claims,
			})
		}
		frr.RepoRules[repo] = authRules
	}

	return frr, nil
}

func (frr FileRuleRepository) GetRulesForRepo(_ context.Context, repo Repository) ([]AuthorizationRule, error) {
	return frr.RepoRules[repo.FullName], nil
}
