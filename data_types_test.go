package main

import "testing"

func TestWildcard_MatchString(t *testing.T) {
	type args struct {
		s        string
		wildcard Wildcard
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Matches a basic wildcard",
			args: args{
				s:        "foobar",
				wildcard: NewWildcard("foo*"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.wildcard.MatchString(tt.args.s); got != tt.want {
				t.Errorf("matchesWildcard() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGitHubClaims_MatchesAnyRule(t *testing.T) {
	testClaims := GitHubClaims{
		Sub:            "repo:example/foo",
		Environment:    "prod",
		JobWorkflowRef: "foobar.yaml",
	}

	type args struct {
		claims GitHubClaims
		rules  []AuthorizationRule
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Matches string by exact match",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("prod"),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Doesn't match string by exact match",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("dev"),
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Matches by wildcard",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/*"),
							"environment": NewWildcards("prod"),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Matches if at least one rule matches",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("prod"),
						},
					},
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/bar"),
							"environment": NewWildcards("prod"),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Doesn't match if no rule matches",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/bar"),
							"environment": NewWildcards("prod"),
						},
					},
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("dev"),
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Matches if at least one of multiple wildcards matches",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("prod", "dev"),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Doesn't match if none of multiple wildcards matches",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[GitHubClaimsField][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("stage", "dev"),
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.claims.MatchesAnyRule(tt.args.rules)
			if got != tt.want {
				t.Errorf("IsCallerAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}
