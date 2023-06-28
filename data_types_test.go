package main

import "testing"

func Test_Wildcard_MatchString(t *testing.T) {
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
