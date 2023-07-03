package main

import (
	"testing"

	"github.com/go-test/deep"
)

func TestNewFileRuleRepository(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		args    args
		want    FileRuleRepository
		wantErr bool
	}{
		{
			name: "Parses a test file",
			args: args{
				file: "./testdata/auth_rule.yaml",
			},
			want: FileRuleRepository{
				RepoRules: map[string][]AuthorizationRule{
					"terrabitz/foo": {
						{Claims: map[GitHubClaimName][]Wildcard{
							"sub":         NewWildcards("repo:terrabitz/*"),
							"environment": NewWildcards("prod"),
						}},
					},
					"terrabitz/bar": {
						{Claims: map[GitHubClaimName][]Wildcard{
							"sub":         NewWildcards("repo:terrabitz/foo"),
							"environment": NewWildcards("dev", "prod"),
						}},
					},
				},
			},
		},
		{
			name: "Parses a test file using single-string rules",
			args: args{
				file: "./testdata/auth_rule_single.yaml",
			},
			want: FileRuleRepository{
				RepoRules: map[string][]AuthorizationRule{
					"terrabitz/foo": {
						{Claims: map[GitHubClaimName][]Wildcard{
							"sub":         NewWildcards("repo:terrabitz/*"),
							"environment": NewWildcards("prod"),
						}},
					},
					"terrabitz/bar": {
						{Claims: map[GitHubClaimName][]Wildcard{
							"sub":         NewWildcards("repo:terrabitz/foo"),
							"environment": NewWildcards("dev", "prod"),
						}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFileRuleRepository(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFileRuleRepository() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := deep.Equal(got, tt.want); diff != nil {
				t.Error(diff)
			}
		})
	}
}
