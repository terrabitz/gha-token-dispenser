package main

import (
	"fmt"
	"net/http"
)

type Error struct {
	InternalMessage string
	ExternalMessage string
	HTTPStatusCode  int
	Wrapped         error
}

func (err *Error) Unwrap() error {
	return err.Wrapped
}

func (err *Error) Error() string {
	if err.Wrapped == nil {
		return err.InternalMessage
	}

	return fmt.Sprintf("%s: %v", err.InternalMessage, err.Wrapped)
}

func (err *Error) New(options ...ErrOption) *Error {
	errCopy := &Error{
		InternalMessage: err.InternalMessage,
		ExternalMessage: err.ExternalMessage,
		HTTPStatusCode:  err.HTTPStatusCode,
		Wrapped:         err.Wrapped,
	}

	for _, option := range options {
		option(errCopy)
	}

	return errCopy
}

type ErrOption func(*Error)

func WithWrappedError(err error) ErrOption {
	return func(e *Error) {
		e.Wrapped = err
	}
}

func WithExternalMessage(msg string) ErrOption {
	return func(e *Error) {
		e.ExternalMessage = msg
	}
}

var (
	ErrInvalidToken Error = Error{
		InternalMessage: "invalid OIDC token",
		ExternalMessage: "invalid OIDC token; make sure to use action terrabitz/dispense-token from a GHA workflow",
		HTTPStatusCode:  http.StatusBadRequest,
	}

	ErrInvalidIssuer Error = Error{
		InternalMessage: "invalid issuer",
		ExternalMessage: "invalid issuer; make sure to use action terrabitz/dispense-token from a GHA workflow",
		HTTPStatusCode:  http.StatusBadRequest,
	}

	ErrInvalidPermissions Error = Error{
		InternalMessage: "invalid permissions requested",
		ExternalMessage: "invalid permissions",
		HTTPStatusCode:  http.StatusUnauthorized,
	}
)
