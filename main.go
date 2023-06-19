package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v53/github"
	"github.com/joho/godotenv"
	cli "github.com/urfave/cli/v2"
)

func main() {
	godotenv.Load()

	var args Args

	app := &cli.App{
		Name: "gh-token-manager",
		Flags: []cli.Flag{
			&cli.Int64Flag{
				Name:        "app-id",
				Destination: &args.AppID,
				Required:    true,
				EnvVars:     []string{"APP_ID"},
			},
			&cli.StringFlag{
				Name:        "private-key-file",
				Destination: &args.PrivateKeyFile,
				Required:    true,
				EnvVars:     []string{"PRIVATE_KEY_FILE"},
			},
		},
		Action: func(cCtx *cli.Context) error {
			return run(args)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

type Args struct {
	AppID          int64
	PrivateKeyFile string
}

func run(args Args) error {
	ghClient, err := NewGitHubAppClient(args)
	if err != nil {
		return fmt.Errorf("couldn't create GitHub client: %w", err)
	}

	githubPublicKeys := GetGitHubPublicKeys()

	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		var req GetTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			fmt.Printf("couldn't decode request: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer r.Body.Close()

		token, err := jwt.ParseWithClaims(req.Token, &GitHubClaims{}, func(token *jwt.Token) (interface{}, error) {
			kid := token.Header["kid"].(string)
			key, ok := githubPublicKeys[kid]
			if !ok {
				return nil, fmt.Errorf("couldn't find public key corresponding to KID '%s", kid)
			}

			return key, nil
		}, jwt.WithValidMethods([]string{"RS256"}))

		if err != nil {
			fmt.Printf("could not parse JWT: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !token.Valid {
			fmt.Println("key is not valid!")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		claims := token.Claims.(*GitHubClaims)
		iss, err := claims.GetIssuer()
		if err != nil {
			fmt.Printf("unable to get issuer: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if iss != "https://token.actions.githubusercontent.com" {
			fmt.Println("issuer isn't GitHub Actions")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		sub, err := claims.GetSubject()
		if err != nil {
			fmt.Printf("unable to get subject: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if sub != "repo:terrabitz/goreleaser-test:ref:refs/heads/main" {
			fmt.Println("repo must be main branch of terrabitz/goreleaser-test")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if claims.JobWorkflowRef != "terrabitz/goreleaser-test/.github/workflows/send-oidc-token.yaml@refs/heads/main" {
			fmt.Println("only permitted from send-oidc-token.yaml")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		installToken, err := ghClient.GetInstallationToken(req.Repo)
		if err != nil {
			fmt.Printf("couldn't get install token: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, installToken)
		fmt.Println("Sent install token!")
	})

	srv := http.Server{
		Addr:    "0.0.0.0:9999",
		Handler: &mux,
	}

	fmt.Printf("listening on %s\n", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("error running server: %w", err)
	}

	return nil
}

func toJson(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

type GetTokenRequest struct {
	Repo  string `json:"repo,omitempty"`
	Token string `json:"token,omitempty"`
}

func GetGitHubPublicKeys() map[string](*rsa.PublicKey) {
	rsakeys := make(map[string]*rsa.PublicKey)

	uri := "https://token.actions.githubusercontent.com/.well-known/jwks"
	resp, _ := http.Get(uri)

	var body GitHubJWKs
	json.NewDecoder(resp.Body).Decode(&body)

	for _, bodykey := range body.Keys {
		key := bodykey
		kid := key.Kid
		rsakey := new(rsa.PublicKey)
		number, _ := base64.RawURLEncoding.DecodeString(key.N)
		rsakey.N = new(big.Int).SetBytes(number)
		rsakey.E = 65537
		rsakeys[kid] = rsakey
	}

	return rsakeys
}

type GitHubJWKs struct {
	Keys []struct {
		N   string   `json:"n"`
		Kty string   `json:"kty"`
		Kid string   `json:"kid"`
		Alg string   `json:"alg"`
		E   string   `json:"e"`
		Use string   `json:"use"`
		X5C []string `json:"x5c"`
		X5T string   `json:"x5t"`
	} `json:"keys"`
}

type GitHubAppClient struct {
	*github.Client
}

func NewGitHubAppClient(args Args) (*GitHubAppClient, error) {
	itr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, args.AppID, args.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("couldn't get transport key: %w", err)
	}

	client := github.NewClient(&http.Client{Transport: itr})
	return &GitHubAppClient{client}, nil
}

func (ghClient *GitHubAppClient) GetInstallationToken(orgAndRepo string) (string, error) {
	parts := strings.SplitN(orgAndRepo, "/", 2)
	org, repo := parts[0], parts[1]
	install, _, err := ghClient.Apps.FindRepositoryInstallation(context.TODO(), org, repo)
	if err != nil {
		return "", fmt.Errorf("couldn't find repo installation: %w", err)
	}

	token, _, err := ghClient.Apps.CreateInstallationToken(context.TODO(), install.GetID(), &github.InstallationTokenOptions{})
	if err != nil {
		return "", fmt.Errorf("couldn't create installation token: %w", err)
	}

	return token.GetToken(), nil
}

type GitHubClaims struct {
	jwt.RegisteredClaims
	Environment          string `json:"environment"`
	Ref                  string `json:"ref"`
	Sha                  string `json:"sha"`
	Repository           string `json:"repository"`
	RepositoryOwner      string `json:"repository_owner"`
	ActorID              string `json:"actor_id"`
	RepositoryVisibility string `json:"repository_visibility"`
	RepositoryID         string `json:"repository_id"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RunID                string `json:"run_id"`
	RunNumber            string `json:"run_number"`
	RunAttempt           string `json:"run_attempt"`
	RunnerEnvironment    string `json:"runner_environment"`
	Actor                string `json:"actor"`
	Workflow             string `json:"workflow"`
	HeadRef              string `json:"head_ref"`
	BaseRef              string `json:"base_ref"`
	EventName            string `json:"event_name"`
	RefType              string `json:"ref_type"`
	JobWorkflowRef       string `json:"job_workflow_ref"`
}
