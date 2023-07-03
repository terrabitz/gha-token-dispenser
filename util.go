package main

import (
	"encoding/json"
	"fmt"
	"reflect"
)

func Any[T any](tt []T, fn func(T) bool) bool {
	for _, t := range tt {
		if fn(t) {
			return true
		}
	}

	return false
}

func All[T any](tt []T, fn func(T) bool) bool {
	for _, t := range tt {
		if !fn(t) {
			return false
		}
	}

	return true
}

func Filter[T any](tt []T, fn func(T) bool) []T {
	var matching []T

	for _, t := range tt {
		if fn(t) {
			matching = append(matching, t)
		}
	}

	return matching
}

func Map[T, U any](tt []T, fn func(T) U) []U {
	var out []U

	for _, t := range tt {
		out = append(out, fn(t))
	}

	return out
}

func Keys[K comparable, V any](m map[K]V) []K {
	var keys []K
	for key := range m {
		keys = append(keys, key)
	}

	return keys
}

func getStringValueByJSONTag(v any, jsonTag string) (string, error) {
	val := reflect.ValueOf(v)
	st := reflect.TypeOf(v)
	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		if jsonField, ok := field.Tag.Lookup("json"); ok {
			if jsonField == jsonTag {
				fieldValue := val.FieldByIndex([]int{i})
				return fieldValue.String(), nil
			}
		}
	}

	return "", fmt.Errorf("couldn't find element '%s'", jsonTag)
}

func toJson(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
