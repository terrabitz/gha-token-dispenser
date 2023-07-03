// Code generated by go-enum DO NOT EDIT.
// Version:
// Revision:
// Build Date:
// Built By:

package main

import (
	"errors"
	"fmt"
)

const (
	// GitHubAccessLevelRead is a GitHubAccessLevel of type Read.
	GitHubAccessLevelRead GitHubAccessLevel = iota + 1
	// GitHubAccessLevelWrite is a GitHubAccessLevel of type Write.
	GitHubAccessLevelWrite
	// GitHubAccessLevelAdmin is a GitHubAccessLevel of type Admin.
	GitHubAccessLevelAdmin
)

var ErrInvalidGitHubAccessLevel = errors.New("not a valid GitHubAccessLevel")

const _GitHubAccessLevelName = "readwriteadmin"

var _GitHubAccessLevelMap = map[GitHubAccessLevel]string{
	GitHubAccessLevelRead:  _GitHubAccessLevelName[0:4],
	GitHubAccessLevelWrite: _GitHubAccessLevelName[4:9],
	GitHubAccessLevelAdmin: _GitHubAccessLevelName[9:14],
}

// String implements the Stringer interface.
func (x GitHubAccessLevel) String() string {
	if str, ok := _GitHubAccessLevelMap[x]; ok {
		return str
	}
	return fmt.Sprintf("GitHubAccessLevel(%d)", x)
}

// IsValid provides a quick way to determine if the typed value is
// part of the allowed enumerated values
func (x GitHubAccessLevel) IsValid() bool {
	_, ok := _GitHubAccessLevelMap[x]
	return ok
}

var _GitHubAccessLevelValue = map[string]GitHubAccessLevel{
	_GitHubAccessLevelName[0:4]:  GitHubAccessLevelRead,
	_GitHubAccessLevelName[4:9]:  GitHubAccessLevelWrite,
	_GitHubAccessLevelName[9:14]: GitHubAccessLevelAdmin,
}

// ParseGitHubAccessLevel attempts to convert a string to a GitHubAccessLevel.
func ParseGitHubAccessLevel(name string) (GitHubAccessLevel, error) {
	if x, ok := _GitHubAccessLevelValue[name]; ok {
		return x, nil
	}
	return GitHubAccessLevel(0), fmt.Errorf("%s is %w", name, ErrInvalidGitHubAccessLevel)
}

// MarshalText implements the text marshaller method.
func (x GitHubAccessLevel) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *GitHubAccessLevel) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseGitHubAccessLevel(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}
