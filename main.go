package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"

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
		b, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("error reading body: %v\n", err)
			return
		}

		defer r.Body.Close()

		token, err := jwt.Parse(string(b), func(token *jwt.Token) (interface{}, error) {
			return githubPublicKeys[token.Header["kid"].(string)], nil
		})

		if !token.Valid {
			fmt.Println("key is not valid!")
			return
		}

		fmt.Println("Token is valid!")

		// fmt.Println(toJson(token))
		sub, err := token.Claims.GetSubject()
		if err != nil {
			fmt.Println("couldn't get subject: %v", err)
			return
		}

		if sub != "repo:terrabitz/goreleaser-test:ref:refs/heads/main" {
			fmt.Println("repo must be main branch of terrabitz/goreleaser-test")
			return
		}

		installToken, err := ghClient.GetInstallationToken()
		if err != nil {
			fmt.Println("couldn't get install token: %v", err)
			return
		}

		fmt.Fprint(w, installToken)
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

func (ghClient *GitHubAppClient) GetInstallationToken() (string, error) {
	// installations, _, err := ghClient.Apps.ListInstallations(context.TODO(), &github.ListOptions{})
	// if err != nil {
	// 	return "", fmt.Errorf("couldn't list installations: %w", err)
	// }

	// fmt.Printf("Creating install token with install ID %d\n", installations[0].GetID())

	install, _, err := ghClient.Apps.FindRepositoryInstallation(context.TODO(), "terrabitz", "goreleaser-test")
	if err != nil {
		return "", fmt.Errorf("couldn't find repo installation: %w", err)
	}

	token, _, err := ghClient.Apps.CreateInstallationToken(context.TODO(), install.GetID(), &github.InstallationTokenOptions{})
	if err != nil {
		return "", fmt.Errorf("couldn't create installation token: %w", err)
	}

	return token.GetToken(), nil
}
