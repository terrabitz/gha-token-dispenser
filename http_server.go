package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type HTTPServer struct {
	*http.Server
	srv *Server
}

func NewHTTPServer(srv *Server) *HTTPServer {
	var mux http.ServeMux
	httpSrv := &HTTPServer{
		Server: &http.Server{
			Addr:    "0.0.0.0:9999",
			Handler: &mux,
		},
		srv: srv,
	}

	mux.Handle("/", httpSrv.GenerateGitHubToken())

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

		res, err := srv.srv.GenerateGitHubToken(r.Context(), req)
		if err != nil {
			fmt.Printf("%v\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Fprint(w, res.Token)
		fmt.Println("Sent install token!")
	})
}
