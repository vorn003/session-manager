package argosapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type appConfig struct {
	AuthBaseURL  string
	Realm        string
	ClientID     string
	ClientSecret string
	Audience     string
	Scope        string
	RedirectURI  string
	APIURL       string
	Verbose      bool
}

type storedToken struct {
	Token *oauth2.Token `json:"token"`
}

func Run(ctx context.Context, apiURL string) (json.RawMessage, error) {
	cfg, err := loadConfig(apiURL)
	if err != nil {
		return nil, err
	}
	if cfg.Verbose && cfg.Audience != "" {
		fmt.Printf("Using audience: %s\n", cfg.Audience)
	}

	tok, err := getAccessToken(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return callArgosAPIWithSingleReauth(ctx, cfg, tok)
}

func RunDefault(ctx context.Context) error {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		return err
	}
	if cfg.Verbose && cfg.Audience != "" {
		fmt.Printf("Using audience: %s\n", cfg.Audience)
	}

	tok, err := getAccessToken(ctx, cfg)
	if err != nil {
		return err
	}

	if cfg.APIURL == "" {
		fmt.Println("Authenticated successfully.")
		fmt.Printf("Access token preview: %.16s...\n", tok.AccessToken)
		fmt.Println("Set ARGOS_API_URL to run an authenticated request.")
		return nil
	}

	_, err = callArgosAPIWithSingleReauth(ctx, cfg, tok)
	return err
}

func loadConfig(apiURL string) (appConfig, error) {
	audience := defaultIfEmpty(os.Getenv("AUTH_AUDIENCE"), os.Getenv("API_AUDIENCE"))

	cfg := appConfig{
		AuthBaseURL:  strings.TrimRight(defaultIfEmpty(os.Getenv("AUTH_BASE_URL"), "https://auth.sdms.arvato-systems.de/auth"), "/"),
		Realm:        defaultIfEmpty(os.Getenv("AUTH_REALM"), "asysid"),
		ClientID:     defaultIfEmpty(os.Getenv("AUTH_CLIENT_ID"), "svc-argos-base-frontend"),
		ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
		Audience:     audience,
		Scope:        defaultIfEmpty(os.Getenv("AUTH_SCOPE"), "openid profile"),
		RedirectURI:  defaultIfEmpty(os.Getenv("AUTH_REDIRECT_URI"), "http://localhost:8000"),
		APIURL:       apiURL,
		Verbose:      strings.EqualFold(os.Getenv("VERBOSE"), "true") || os.Getenv("VERBOSE") == "1",
	}
	return cfg, nil
}

func loadConfigFromEnv() (appConfig, error) {
	defaultAPIURL := "https://api.sdms.arvato-systems.de/argos/storage-base/v2/query/instance/containers?containerTagName=Customer&containerTagValue=Aldi&containerTagValueOperator=LIKE&showTags=Customer,Debitor"
	apiURL := defaultIfEmpty(os.Getenv("ARGOS_API_URL"), defaultAPIURL)
	audience := defaultIfEmpty(os.Getenv("AUTH_AUDIENCE"), os.Getenv("API_AUDIENCE"))

	cfg := appConfig{
		AuthBaseURL: strings.TrimRight(defaultIfEmpty(os.Getenv("AUTH_BASE_URL"), "https://auth.sdms.arvato-systems.de/auth"), "/"),
		Realm:       defaultIfEmpty(os.Getenv("AUTH_REALM"), "asysid"),
		ClientID:    defaultIfEmpty(os.Getenv("AUTH_CLIENT_ID"), "svc-argos-base-frontend"),
		ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
		Audience:    audience,
		Scope:       defaultIfEmpty(os.Getenv("AUTH_SCOPE"), "openid profile"),
		RedirectURI: defaultIfEmpty(os.Getenv("AUTH_REDIRECT_URI"), "http://localhost:8000"),
		APIURL:      apiURL,
		Verbose:     strings.EqualFold(os.Getenv("VERBOSE"), "true") || os.Getenv("VERBOSE") == "1",
	}

	return cfg, nil
}

func oauthConfig(cfg appConfig) *oauth2.Config {
	base := fmt.Sprintf("%s/realms/%s/protocol/openid-connect", cfg.AuthBaseURL, cfg.Realm)
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Scopes:       strings.Fields(cfg.Scope),
		Endpoint: oauth2.Endpoint{
			AuthURL:  base + "/auth",
			TokenURL: base + "/token",
		},
	}
}

func getAccessToken(ctx context.Context, cfg appConfig) (*oauth2.Token, error) {
	path, err := tokenFilePath()
	if err != nil {
		return nil, err
	}

	ocfg := oauthConfig(cfg)
	savedToken, loadErr := loadToken(path)

	if errors.Is(loadErr, os.ErrNotExist) {
		if cfg.Verbose {
			fmt.Println("No cached token found. Starting fresh login...")
		}
		return doFreshLogin(ctx, ocfg, cfg, path)
	}
	if loadErr != nil {
		return nil, loadErr
	}

	// Audience mismatch — must re-login
	if cfg.Audience != "" && !tokenHasAudience(savedToken.AccessToken, cfg.Audience) {
		if cfg.Verbose {
			fmt.Printf("Cached token missing required audience %q. Starting fresh login...\n", cfg.Audience)
		}
		return doFreshLogin(ctx, ocfg, cfg, path)
	}

	// Prefer silent refresh via refresh token
	if savedToken.RefreshToken != "" {
		if cfg.Verbose {
			fmt.Println("Refreshing token silently...")
		}
		tsrc := ocfg.TokenSource(ctx, savedToken)
		refreshed, err := tsrc.Token()
		if err == nil {
			if err := saveToken(path, refreshed); err != nil {
				return nil, err
			}
			return refreshed, nil
		}
		if cfg.Verbose {
			fmt.Printf("Token refresh failed (%v). Starting fresh login...\n", err)
		}
		return doFreshLogin(ctx, ocfg, cfg, path)
	}

	// No refresh token — use access token if still valid
	if savedToken.Valid() {
		if cfg.Verbose {
			fmt.Println("Using existing valid token.")
		}
		return savedToken, nil
	}

	if cfg.Verbose {
		fmt.Println("Token expired and no refresh token available. Starting fresh login...")
	}
	return doFreshLogin(ctx, ocfg, cfg, path)
}

func doFreshLogin(ctx context.Context, ocfg *oauth2.Config, cfg appConfig, path string) (*oauth2.Token, error) {
	fresh, err := freshLogin(ctx, ocfg, cfg)
	if err != nil {
		return nil, err
	}
	if err := saveToken(path, fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

func freshLogin(ctx context.Context, cfg *oauth2.Config, appCfg appConfig) (*oauth2.Token, error) {
	redirectURL, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect uri: %w", err)
	}
	callbackPath := redirectURL.Path
	if callbackPath == "" {
		callbackPath = "/"
	}

	state, err := randomState(24)
	if err != nil {
		return nil, err
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	server := &http.Server{Addr: redirectURL.Host}

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			errCh <- errors.New("oauth state mismatch")
			return
		}
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			desc := r.URL.Query().Get("error_description")
			http.Error(w, "Authentication failed", http.StatusBadRequest)
			errCh <- fmt.Errorf("oauth error: %s (%s)", errParam, desc)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errCh <- errors.New("missing authorization code")
			return
		}

		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body style="font-family:sans-serif;text-align:center;padding-top:40px;">
<h2 style="color:green;">Authentication successful</h2>
<p>You can close this window now.</p>
</body></html>`))
		codeCh <- code
	})

	server.Handler = mux

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctxStop, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = server.Shutdown(ctxStop)
		})
	}
	defer shutdown()

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	authCodeOpts := oauthAuthCodeOptions(appCfg)

	authURL := cfg.AuthCodeURL(state, authCodeOpts...)
	if appCfg.Verbose {
		fmt.Printf("Opening browser: %s\n", authURL)
	}
	if err := openBrowser(authURL); err != nil {
		fmt.Printf("Could not open browser automatically: %v\n", err)
		fmt.Printf("Open this URL manually:\n%s\n", authURL)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return nil, err
	case <-waitCtx.Done():
		return nil, errors.New("timeout waiting for OAuth callback")
	}

	token, err := cfg.Exchange(ctx, code, authCodeOpts...)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	return token, nil
}

type apiError struct {
	StatusCode int
	Body       string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("api request failed with status %d", e.StatusCode)
}

func callArgosAPI(apiURL, accessToken string) (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, &apiError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return json.RawMessage(body), nil
}

func tokenFilePath() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cacheDir, "sshmenu")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "argos_token.json"), nil
}

func saveToken(path string, tok *oauth2.Token) error {
	blob, err := json.MarshalIndent(storedToken{Token: tok}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}

func loadToken(path string) (*oauth2.Token, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload storedToken
	if err := json.Unmarshal(blob, &payload); err != nil {
		return nil, err
	}
	if payload.Token == nil {
		return nil, errors.New("token file is empty")
	}
	return payload.Token, nil
}

func randomState(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func openBrowser(url string) error {
	if err := exec.Command("wslview", url).Run(); err == nil {
		return nil
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return errors.New("unsupported platform")
	}
	return cmd.Run()
}

func defaultIfEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func oauthAuthCodeOptions(cfg appConfig) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if cfg.Audience != "" {
		opts = append(opts, oauth2.SetAuthURLParam("audience", cfg.Audience))
		opts = append(opts, oauth2.SetAuthURLParam("resource", cfg.Audience))
	}
	return opts
}

func deriveAudienceFromAPIURL(apiURL string) string {
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func printTokenDiagnostics(rawToken string) {
	claims, err := parseJWTClaims(rawToken)
	if err != nil {
		fmt.Printf("Token diagnostics unavailable: %v\n", err)
		return
	}
	exp, _ := claims.GetExpirationTime()
	fmt.Printf("Token iss=%v aud=%v azp=%v scope=%v exp=%v\n", claims["iss"], claims["aud"], claims["azp"], claims["scope"], exp)
}

func parseJWTClaims(rawToken string) (jwt.MapClaims, error) {
	tok, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unexpected claims type")
	}
	return claims, nil
}

func tokenHasAudience(rawToken, requiredAudience string) bool {
	claims, err := parseJWTClaims(rawToken)
	if err != nil {
		return false
	}
	aud, err := claims.GetAudience()
	if err != nil {
		return false
	}
	for _, value := range aud {
		if value == requiredAudience {
			return true
		}
	}
	return false
}

func callArgosAPIWithSingleReauth(ctx context.Context, cfg appConfig, token *oauth2.Token) (json.RawMessage, error) {
	body, err := callArgosAPI(cfg.APIURL, token.AccessToken)
	if err == nil {
		return body, nil
	}

	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		return nil, err
	}

	printTokenDiagnostics(token.AccessToken)
	fmt.Println("401 returned by API. Re-authenticating once with a fresh token...")

	freshToken, loginErr := freshLogin(ctx, oauthConfig(cfg), cfg)
	if loginErr != nil {
		return nil, fmt.Errorf("re-login failed after 401: %w", loginErr)
	}
	printTokenDiagnostics(freshToken.AccessToken)

	if path, pathErr := tokenFilePath(); pathErr == nil {
		_ = saveToken(path, freshToken)
	}

	return callArgosAPI(cfg.APIURL, freshToken.AccessToken)
}
