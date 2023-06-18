package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	ghinstallation "github.com/bradleyfalzon/ghinstallation/v2"
	github "github.com/google/go-github/v53/github"
	"github.com/joho/godotenv"
	cli "github.com/urfave/cli/v2"
	"golang.org/x/oauth2"
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
	itr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, args.AppID, args.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("couldn't get transport key: %w", err)
	}

	client := github.NewClient(&http.Client{Transport: itr})

	installations, _, err := client.Apps.ListInstallations(context.TODO(), &github.ListOptions{})
	if err != nil {
		return fmt.Errorf("couldn't list installations: %w", err)
	}

	fmt.Printf("Creating install token with install ID %d\n", installations[0].GetID())

	token, _, err := client.Apps.CreateInstallationToken(context.TODO(), installations[0].GetID(), &github.InstallationTokenOptions{})
	if err != nil {
		return fmt.Errorf("couldn't create installation token: %w", err)
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token.GetToken()},
	)
	tc := oauth2.NewClient(ctx, ts)

	installationClient := github.NewClient(tc)

	// list all repositories for the authenticated user
	repos, _, err := installationClient.Repositories.List(context.TODO(), "terrabitz", &github.RepositoryListOptions{})
	if err != nil {
		return fmt.Errorf("couldn't list repos: %w", err)
	}
	fmt.Println(toJson(repos))

	return nil
}

func toJson(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
