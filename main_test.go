package main

import (
	"testing"
)

func Test_getFieldByJSONTag(t *testing.T) {
	type Foo struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}

	type args struct {
		v       any
		jsonTag string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Gets a value for a specific JSON string",
			args: args{
				v:       Foo{Foo: "123", Bar: "456"},
				jsonTag: "foo",
			},
			want: "123",
		},
		{
			name: "Returns error if a specific JSON string is not found",
			args: args{
				v:       Foo{Foo: "123", Bar: "456"},
				jsonTag: "asdf",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getStringValueByJSONTag(tt.args.v, tt.args.jsonTag)
			if (err != nil) != tt.wantErr {
				t.Errorf("getFieldValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getFieldValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaimMatchesAnyRule(t *testing.T) {
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
						Fields: map[string][]Wildcard{
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
						Fields: map[string][]Wildcard{
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
						Fields: map[string][]Wildcard{
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
						Fields: map[string][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("prod"),
						},
					},
					{
						Fields: map[string][]Wildcard{
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
						Fields: map[string][]Wildcard{
							"sub":         NewWildcards("repo:example/bar"),
							"environment": NewWildcards("prod"),
						},
					},
					{
						Fields: map[string][]Wildcard{
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
						Fields: map[string][]Wildcard{
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
						Fields: map[string][]Wildcard{
							"sub":         NewWildcards("repo:example/foo"),
							"environment": NewWildcards("stage", "dev"),
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Errors if rule references a bad field",
			args: args{
				claims: testClaims,
				rules: []AuthorizationRule{
					{
						Fields: map[string][]Wildcard{
							"asdfasdf":    NewWildcards("repo:example/*"),
							"environment": NewWildcards("prod"),
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ClaimMatchesAnyRule(tt.args.claims, tt.args.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsCallerAuthorized() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsCallerAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}
