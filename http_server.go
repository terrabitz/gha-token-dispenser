package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type HTTPServer struct {
	*http.Server
	tokenSrv *TokenService
}

func NewHTTPServer(srv *TokenService) *HTTPServer {
	var mux http.ServeMux
	httpSrv := &HTTPServer{
		Server: &http.Server{
			Addr:    "0.0.0.0:9999",
			Handler: &mux,
		},
		tokenSrv: srv,
	}

	mux.Handle("/token", httpSrv.GenerateGitHubToken())

	return httpSrv
}

func (srv *HTTPServer) GenerateGitHubToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			return
		}

		var req GetTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			fmt.Printf("couldn't decode request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer r.Body.Close()

		res, err := srv.tokenSrv.GenerateGitHubToken(r.Context(), req)
		if err != nil {
			res := ErrorMessage{
				Error: "something went wrong; please open a ticket at https://github.com/terrabitz/gha-token-dispenser",
				Code:  http.StatusInternalServerError,
			}

			var appError *Error
			if errors.As(err, &appError) {
				res.Error = appError.ExternalMessage
				res.Code = appError.HTTPStatusCode
			}

			fmt.Printf("%v\n", err)
			w.WriteHeader(res.Code)
			_ = json.NewEncoder(w).Encode(res)
			return
		}

		fmt.Fprint(w, res.Token)
		fmt.Println("Sent install token!")
	})
}

type ErrorMessage struct {
	Error string `json:"error,omitempty"`
	Code  int    `json:"code,omitempty"`
}
