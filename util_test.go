package main

import "testing"

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
