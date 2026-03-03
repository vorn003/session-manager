package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

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

func main() {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	if cfg.Verbose && cfg.Audience != "" {
		fmt.Printf("Using audience: %s\n", cfg.Audience)
	}

	tok, err := getAccessToken(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}

	if cfg.APIURL == "" {
		fmt.Println("Authenticated successfully.")
		fmt.Printf("Access token preview: %.16s...\n", tok.AccessToken)
		fmt.Println("Set ARGOS_API_URL to run an authenticated request.")
		return
	}

	if err := callAPI(cfg.APIURL, tok.AccessToken); err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
			printTokenDiagnostics(tok.AccessToken)
			fmt.Println("401 returned by API. Re-authenticating once with a fresh token...")
			freshToken, loginErr := freshLogin(context.Background(), oauthConfig(cfg), cfg)
			if loginErr != nil {
				log.Fatalf("re-login failed after 401: %v", loginErr)
			}
			printTokenDiagnostics(freshToken.AccessToken)
			path, pathErr := tokenFilePath()
			if pathErr == nil {
				_ = saveToken(path, freshToken)
			}
			if retryErr := callAPI(cfg.APIURL, freshToken.AccessToken); retryErr == nil {
				return
			} else {
				log.Fatal(retryErr)
			}
		}
		log.Fatal(err)
	}
}

func loadConfigFromEnv() (appConfig, error) {
	defaultAPIURL := "https://api.sdms.arvato-systems.de/argos/storage-base/v2/query/instance/containers?containerTagName=Customer&containerTagValue=Aldi&containerTagValueOperator=LIKE&showTags=Customer,Debitor"
	apiURL := defaultIfEmpty(os.Getenv("ARGOS_API_URL"), defaultAPIURL)
	audience := defaultIfEmpty(os.Getenv("AUTH_AUDIENCE"), os.Getenv("API_AUDIENCE"))
	if audience == "" {
		audience = deriveAudienceFromAPIURL(apiURL)
	}

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
	fileAge, _ := tokenFileAge(path)

	savedToken, loadErr := loadToken(path)
	switch {
	case errors.Is(loadErr, os.ErrNotExist), fileAge > 30*time.Minute:
		if cfg.Verbose {
			fmt.Println("No valid token found or token file too old. Starting fresh login...")
		}
		fresh, err := freshLogin(ctx, ocfg, cfg)
		if err != nil {
			return nil, err
		}
		if err := saveToken(path, fresh); err != nil {
			return nil, err
		}
		return fresh, nil
	case loadErr != nil:
		return nil, loadErr
	}

	if fileAge > 5*time.Minute {
		if cfg.Verbose {
			fmt.Println("Attempting token refresh...")
		}
		tsrc := ocfg.TokenSource(ctx, savedToken)
		refreshed, err := tsrc.Token()
		if err != nil {
			if cfg.Verbose {
				fmt.Printf("Refresh failed (%v). Starting fresh login...\n", err)
			}
			fresh, loginErr := freshLogin(ctx, ocfg, cfg)
			if loginErr != nil {
				return nil, loginErr
			}
			if err := saveToken(path, fresh); err != nil {
				return nil, err
			}
			return fresh, nil
		}
		if err := saveToken(path, refreshed); err != nil {
			return nil, err
		}
		return refreshed, nil
	}

	if cfg.Verbose {
		fmt.Println("Using existing token.")
	}
	if cfg.Audience != "" && !tokenHasAudience(savedToken.AccessToken, cfg.Audience) {
		if cfg.Verbose {
			fmt.Printf("Cached token is missing required audience %q. Starting fresh login...\n", cfg.Audience)
		}
		fresh, err := freshLogin(ctx, ocfg, cfg)
		if err != nil {
			return nil, err
		}
		if err := saveToken(path, fresh); err != nil {
			return nil, err
		}
		return fresh, nil
	}
	return savedToken, nil
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

	authCodeOpts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if appCfg.Audience != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("audience", appCfg.Audience))
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("resource", appCfg.Audience))
	}

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

func callAPI(apiURL, accessToken string) error {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("API status: %d\n", resp.StatusCode)
	fmt.Println(string(body))

	if resp.StatusCode >= 400 {
		return &apiError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return nil
}

func tokenFilePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(configDir, "sshmenu")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "argos_token.json"), nil
}

func tokenFileAge(path string) (time.Duration, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return time.Since(info.ModTime()), nil
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

func deriveAudienceFromAPIURL(apiURL string) string {
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func printTokenDiagnostics(rawToken string) {
	claims, err := decodeJWTClaims(rawToken)
	if err != nil {
		fmt.Printf("Token diagnostics unavailable: %v\n", err)
		return
	}
	fmt.Printf("Token iss=%v aud=%v azp=%v scope=%v exp=%v\n", claims["iss"], claims["aud"], claims["azp"], claims["scope"], claims["exp"])
}

func decodeJWTClaims(rawToken string) (map[string]any, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func tokenHasAudience(rawToken, requiredAudience string) bool {
	claims, err := decodeJWTClaims(rawToken)
	if err != nil {
		return false
	}

	aud, exists := claims["aud"]
	if !exists {
		return false
	}

	switch audValue := aud.(type) {
	case string:
		return audValue == requiredAudience
	case []any:
		for _, value := range audValue {
			if str, ok := value.(string); ok && str == requiredAudience {
				return true
			}
		}
	case float64:
		return strconv.FormatFloat(audValue, 'f', -1, 64) == requiredAudience
	}

	return false
}
