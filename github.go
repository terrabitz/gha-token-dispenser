package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v53/github"
)

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

func (ghClient *GitHubAppClient) GetInstallationToken(ctx context.Context, repo Repository, perms PermissionSet) (string, error) {
	install, _, err := ghClient.Apps.FindRepositoryInstallation(ctx, repo.Owner, repo.Name)
	if err != nil {
		return "", fmt.Errorf("couldn't find repo installation: %w", err)
	}

	installPerms := &github.InstallationPermissions{
		Contents: perms.GetAccessLevelString("contents"),
	}

	token, _, err := ghClient.Apps.CreateInstallationToken(ctx, install.GetID(), &github.InstallationTokenOptions{
		Repositories: []string{repo.Name},
		Permissions:  installPerms,
	})
	if err != nil {
		return "", fmt.Errorf("couldn't create installation token: %w", err)
	}

	return token.GetToken(), nil
}
