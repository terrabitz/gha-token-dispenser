package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	cli "github.com/urfave/cli/v2"
)

const githubTokenIssuer = "https://token.actions.githubusercontent.com"

type Args struct {
	AppID          int64
	PrivateKeyFile string
	RulesFile      string
}

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
			&cli.StringFlag{
				Name:        "rules-file",
				Destination: &args.RulesFile,
				EnvVars:     []string{"RULES_FILE"},
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

func run(args Args) error {
	ghClient, err := NewGitHubAppClient(args)
	if err != nil {
		return fmt.Errorf("couldn't create GitHub client: %w", err)
	}

	provider, err := oidc.NewProvider(context.TODO(), githubTokenIssuer)
	if err != nil {
		return fmt.Errorf("couldn't create OIDC provider: %w", err)
	}

	oidcVerifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})

	var authRulesRepo AuthRuleRepository = MemRuleRepository{}
	if args.RulesFile != "" {
		authRulesRepo, err = NewFileRuleRepository(args.RulesFile)
		if err != nil {
			return fmt.Errorf("couldn't read authorization rules from file: %w", err)
		}

		fmt.Printf("using rules file at '%s'\n", args.RulesFile)
	}

	srv := TokenService{
		ghClient:     ghClient,
		authRules:    authRulesRepo,
		oidcVerifier: oidcVerifier,
	}

	httpSrv := NewHTTPServer(&srv)
	fmt.Printf("listening on %s\n", httpSrv.Addr)
	if err := httpSrv.ListenAndServe(); err != nil {
		return fmt.Errorf("error running server: %w", err)
	}

	return nil
}

type TokenService struct {
	ghClient     *GitHubAppClient
	authRules    AuthRuleRepository
	oidcVerifier *oidc.IDTokenVerifier
}

type AuthRuleRepository interface {
	GetRulesForRepo(context.Context, Repository) ([]AuthorizationRule, error)
}

type GetTokenRequest struct {
	Repo        string        `json:"repo"`
	OIDCToken   string        `json:"token"`
	Permissions PermissionSet `json:"permissions"`
}

type GetTokenResponse struct {
	Token string `json:"token,omitempty"`
}

func (srv *TokenService) GenerateGitHubToken(ctx context.Context, req GetTokenRequest) (GetTokenResponse, error) {
	idToken, err := srv.oidcVerifier.Verify(ctx, req.OIDCToken)
	if err != nil {
		return GetTokenResponse{}, ErrInvalidToken.New(WithWrappedError(err))
	}

	if idToken.Issuer != githubTokenIssuer {
		return GetTokenResponse{}, errors.New("issuer isn't GitHub Actions")
	}

	targetRepo, err := ParseRepository(req.Repo)
	if err != nil {
		return GetTokenResponse{}, fmt.Errorf("invalid repository: %w", err)
	}

	if len(req.Permissions) == 0 {
		return GetTokenResponse{}, errors.New("permissions must be included")
	}

	var claims GitHubClaims
	if err := idToken.Claims(&claims); err != nil {
		return GetTokenResponse{}, fmt.Errorf("could not extract GitHub custom claims: %w", err)
	}

	if claims.RepositoryOwner != targetRepo.Owner {
		return GetTokenResponse{}, errors.New("caller must have same owner as target")
	}

	rules, err := srv.authRules.GetRulesForRepo(ctx, targetRepo)
	if err != nil {
		return GetTokenResponse{}, fmt.Errorf("could not get rules for repository: %w", err)
	}

	if !claims.MatchesAnyRule(rules) {
		return GetTokenResponse{}, fmt.Errorf("caller is not authorized to generate a token for repo %s", req.Repo)
	}

	matchingRules := claims.GetMatchingRules(rules)
	perms := Map(matchingRules, func(rule AuthorizationRule) PermissionSet { return rule.Permissions })
	maxPerms := MergePermissions(perms)

	for requestedPerm, requestedAccessLevel := range req.Permissions {
		maxAccessLevel, ok := maxPerms[requestedPerm]
		if !ok {
			return GetTokenResponse{}, fmt.Errorf("permission '%s' is not allowed ", requestedPerm)
		}

		if requestedAccessLevel.GreaterThan(maxAccessLevel) {
			err := ErrInvalidPermissions.New(
				WithExternalMessage(fmt.Sprintf("permission '%s' may only be requested at access level '%s' and below", requestedPerm, maxAccessLevel)),
			)
			return GetTokenResponse{}, err
		}
	}

	installToken, err := srv.ghClient.GetInstallationToken(ctx, targetRepo, req.Permissions)
	if err != nil {
		return GetTokenResponse{}, fmt.Errorf("couldn't get install token: %w", err)
	}

	fmt.Println("Sending install token!")

	return GetTokenResponse{Token: installToken}, nil
}
