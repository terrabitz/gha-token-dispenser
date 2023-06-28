package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-github/v53/github"
	"github.com/joho/godotenv"
	cli "github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
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

	srv := Server{
		ghClient:     ghClient,
		authRules:    authRulesRepo,
		oidcVerifier: oidcVerifier,
	}

	var mux http.ServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

		res, err := srv.GenerateGitHubToken(r.Context(), req)
		if err != nil {
			fmt.Printf("%v\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Fprint(w, res.Token)
		fmt.Println("Sent install token!")
	})

	httpSrv := http.Server{
		Addr:    "0.0.0.0:9999",
		Handler: &mux,
	}

	fmt.Printf("listening on %s\n", httpSrv.Addr)
	if err := httpSrv.ListenAndServe(); err != nil {
		return fmt.Errorf("error running server: %w", err)
	}

	return nil
}

type Server struct {
	ghClient     *GitHubAppClient
	authRules    AuthRuleRepository
	oidcVerifier *oidc.IDTokenVerifier
}

type GetTokenRequest struct {
	Repo      string `json:"repo,omitempty"`
	OIDCToken string `json:"token,omitempty"`
}

type GetTokenResponse struct {
	Token string `json:"token,omitempty"`
}

func (srv *Server) GenerateGitHubToken(ctx context.Context, req GetTokenRequest) (GetTokenResponse, error) {
	targetRepo, err := ParseRepository(req.Repo)
	if err != nil {
		return GetTokenResponse{}, fmt.Errorf("couldn't parse repository: %w", err)
	}

	idToken, err := srv.oidcVerifier.Verify(ctx, req.OIDCToken)
	if err != nil {
		return GetTokenResponse{}, fmt.Errorf("invalid token: %w", err)
	}

	if idToken.Issuer != githubTokenIssuer {
		return GetTokenResponse{}, errors.New("issuer isn't GitHub Actions")
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

	authorized, err := ClaimMatchesAnyRule(claims, rules)
	if err != nil {
		return GetTokenResponse{}, fmt.Errorf("error while making authorization decision: %w", err)
	}

	if !authorized {
		return GetTokenResponse{}, fmt.Errorf("caller is not authorized to generate a token for repo %s", req.Repo)
	}

	installToken, err := srv.ghClient.GetInstallationToken(ctx, targetRepo)
	if err != nil {
		return GetTokenResponse{}, fmt.Errorf("couldn't get install token: %w", err)
	}

	fmt.Println("Sending install token!")

	return GetTokenResponse{Token: installToken}, nil
}

func toJson(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
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

func (ghClient *GitHubAppClient) GetInstallationToken(ctx context.Context, repo Repository) (string, error) {
	install, _, err := ghClient.Apps.FindRepositoryInstallation(ctx, repo.Owner, repo.Name)
	if err != nil {
		return "", fmt.Errorf("couldn't find repo installation: %w", err)
	}

	token, _, err := ghClient.Apps.CreateInstallationToken(ctx, install.GetID(), &github.InstallationTokenOptions{
		Repositories: []string{repo.Name},
		Permissions: &github.InstallationPermissions{
			Contents: github.String("write"),
		},
	})
	if err != nil {
		return "", fmt.Errorf("couldn't create installation token: %w", err)
	}

	return token.GetToken(), nil
}

type GitHubClaims struct {
	Jti                  string `json:"jti"`
	Sub                  string `json:"sub"`
	Environment          string `json:"environment"`
	Aud                  string `json:"aud"`
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
	Iss                  string `json:"iss"`
}

type Repository struct {
	Name     string
	Owner    string
	FullName string
}

func ParseRepository(orgAndRepo string) (Repository, error) {
	parts := strings.Split(orgAndRepo, "/")
	if len(parts) != 2 {
		return Repository{}, fmt.Errorf("invalid format for repository '%s'; must use 'org/name' format", orgAndRepo)
	}

	return Repository{
		Owner:    parts[0],
		Name:     parts[1],
		FullName: orgAndRepo,
	}, nil
}

type AuthorizationRule struct {
	Fields map[string][]string
}

func ClaimMatchesAnyRule(claims GitHubClaims, rules []AuthorizationRule) (bool, error) {
	for _, rule := range rules {
		matches, err := claimMatchesRule(claims, rule)
		if err != nil {
			return false, fmt.Errorf("error matching rule: %w", err)
		}

		if matches {
			return true, nil
		}
	}

	return false, nil
}

func claimMatchesRule(claims GitHubClaims, rule AuthorizationRule) (bool, error) {
	for field, wildcards := range rule.Fields {
		claimValue, err := getStringValueByJSONTag(claims, field)
		if err != nil {
			return false, fmt.Errorf("couldn't match rules: %w", err)
		}

		if !Any(wildcards, func(wildcard string) bool {
			return matchesWildcard(claimValue, wildcard)
		}) {
			return false, nil
		}
	}

	return true, nil
}

func Any[T any](tt []T, fn func(T) bool) bool {
	for _, t := range tt {
		if fn(t) {
			return true
		}
	}

	return false
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

func matchesWildcard(s, wildcard string) bool {
	escaped := regexp.QuoteMeta(wildcard)
	expanded := strings.Replace(escaped, "\\*", ".*", -1)
	anchored := fmt.Sprintf("^%s$", expanded)
	re, _ := regexp.Compile(anchored)
	return re.MatchString(s)
}

type AuthRuleRepository interface {
	GetRulesForRepo(context.Context, Repository) ([]AuthorizationRule, error)
}

type MemRuleRepository struct{}

func (_ MemRuleRepository) GetRulesForRepo(_ context.Context, repo Repository) ([]AuthorizationRule, error) {
	rules := map[string][]AuthorizationRule{
		"terrabitz/goreleaser-test": {{
			Fields: map[string][]string{
				"sub":              {"repo:terrabitz/goreleaser-test:*"},
				"job_workflow_ref": {"terrabitz/goreleaser-test/.github/workflows/send-oidc-token.yaml@*"},
			},
		}},
	}

	rule, ok := rules[repo.FullName]
	if !ok {
		return nil, fmt.Errorf("repo '%s' isn't defined in the map", repo.FullName)
	}

	return rule, nil
}

type FileRuleRepository struct {
	RepoRules map[string][]AuthorizationRule
}

type FileRuleRepositoryConfig struct {
	RepoRules map[string][]struct {
		Fields map[string]SingleOrMulti `yaml:"fields,inline"`
	} `yaml:"repo_rules,inline"`
}

type SingleOrMulti []string

func (a *SingleOrMulti) UnmarshalYAML(value *yaml.Node) error {
	var multi []string
	err := value.Decode(&multi)
	if err != nil {
		var single string
		err := value.Decode(&single)
		if err != nil {
			return err
		}
		*a = []string{single}
	} else {
		*a = multi
	}
	return nil
}

func NewFileRuleRepository(file string) (FileRuleRepository, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return FileRuleRepository{}, fmt.Errorf("couldn't read file '%s': %w", file, err)
	}

	var config FileRuleRepositoryConfig
	yaml.Unmarshal(b, &config)

	frr := FileRuleRepository{
		RepoRules: map[string][]AuthorizationRule{},
	}
	for repo, rules := range config.RepoRules {
		var authRules []AuthorizationRule
		for _, rule := range rules {
			fields := map[string][]string{}
			for field, values := range rule.Fields {
				fields[field] = []string(values)
			}

			authRules = append(authRules, AuthorizationRule{
				Fields: fields,
			})
		}
		frr.RepoRules[repo] = authRules
	}

	return frr, nil
}

func (frr FileRuleRepository) GetRulesForRepo(_ context.Context, repo Repository) ([]AuthorizationRule, error) {
	return frr.RepoRules[repo.FullName], nil
}
