package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/coreos/go-oidc"
	rootcerts "github.com/hashicorp/go-rootcerts"
	"golang.org/x/net/html"
	"golang.org/x/oauth2"
)

type (
	TokenType string
	GrantType string
)

var (
	TokenTypeAccessToken TokenType = "urn:ietf:params:oauth:token-type:access_token"
	// TokenTypeOktaWebSSOToken is a URN for a token type that appears to be unique to Okta,  that is not documented anywhere.
	//
	// https://www.linkedin.com/pulse/oktas-aws-cli-app-mysterious-case-powerful-okta-apis-chaim-sanders/
	TokenTypeOktaWebSSOToken TokenType = "urn:okta:oauth:token-type:web_sso_token"
	TokenTypeIDToken         TokenType = "urn:ietf:params:oauth:token-type:id_token"
	GrantTypeTokenExchange   GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
)

var (
	ErrNoSAMLAssertion = errors.New("no saml assertion")
	// ErrUnauthorized indicates that the Okta server rejected the request.
	ErrUnauthorized = errors.New("unauthorized")
)

// stateBufSize is the size of the buffer used to generate the state parameter.
// 43 is a magic number - It generates states that are not too short or long for Okta's validation.
const stateBufSize = 43

func NewHTTPClient() *http.Client {
	// Some Darwin systems require certs to be loaded from the system certificate store or attempts to verify SSL certs on internal websites may fail.
	tr := http.DefaultTransport
	if certs, err := rootcerts.LoadSystemCAs(); err == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certs,
			},
		}
	}

	return &http.Client{Transport: LogRoundTripper{tr}}
}

func DiscoverOAuth2Config(ctx context.Context, domain, clientID string) (*oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, domain)
	if err != nil {
		log.Printf("%s", err)
		return nil, fmt.Errorf("couldn't discover OIDC configuration for %s: %w", domain, err)
	}

	cfg := oauth2.Config{
		ClientID: clientID,
		Endpoint: provider.Endpoint(),
		Scopes:   []string{"openid", "profile", "okta.apps.read", "okta.apps.sso"},
	}

	return &cfg, nil
}

// OAuth2CallbackState encapsulates all of the information from an oauth2 callback.
//
// To retrieve the Code from the struct, you must use the Verify(string) function.
type OAuth2CallbackState struct {
	code             string
	state            string
	errorMessage     string
	errorDescription string
}

// FromRequest parses the given http.Request and populates the OAuth2CallbackState with those values.
func (o *OAuth2CallbackState) FromRequest(r *http.Request) {
	o.errorMessage = r.FormValue("error")
	o.errorDescription = r.FormValue("error_description")
	o.state = r.FormValue("state")
	o.code = r.FormValue("code")
}

// Verify safely compares the given state with the state from the OAuth2 callback.
//
// If they match, the code is returned, with a nil value. Otherwise, an empty string and an error is returned.
func (o OAuth2CallbackState) Verify(expectedState string) (string, error) {
	if o.errorMessage != "" {
		return "", OAuth2Error{Reason: o.errorMessage, Description: o.errorDescription}
	}

	if strings.Compare(o.state, expectedState) != 0 {
		return "", OAuth2Error{Reason: "invalid_state", Description: "state mismatch"}
	}

	return o.code, nil
}

// OAuth2CallbackHandler returns a http.Handler, channel and function triple.
//
// The http handler will accept exactly one request, which it will assume is an OAuth2 callback, parse it into an OAuth2CallbackState and then provide it to the given channel. Subsequent requests will be silently ignored.
//
// The function may be called to ensure that the channel is closed. The channel is closed when a request is received. In general, it is a good idea to ensure this function is called in a defer() block.
func OAuth2CallbackHandler() (http.Handler, <-chan OAuth2CallbackState, func()) {
	// TODO: It is possible for the caller to close a panic() if they execute the function in the triplet while the handler has not yet received a request.
	// That caller is us, so I don't care that much, but that probably indicates that this design is smelly.
	//
	// We should look at the Go SDK to see how they handle similar cases - channels that are not bound by a timer, or similar.

	ch := make(chan OAuth2CallbackState, 1)
	var reqHandle, closeHandle sync.Once
	closeFn := func() {
		closeHandle.Do(func() {
			close(ch)
		})
	}

	fn := func(w http.ResponseWriter, r *http.Request) {
		// This can sometimes be called multiple times, depending on the browser.
		// We will simply ignore any other requests and only serve the first.
		reqHandle.Do(func() {
			var state OAuth2CallbackState
			state.FromRequest(r)
			ch <- state
			closeFn()
		})

		// We still want to provide feedback to the end-user.
		fmt.Fprintln(w, "You may close this window now.")
	}

	return http.HandlerFunc(fn), ch, closeFn
}

type OAuth2Error struct {
	Reason      string
	Description string
}

func (e OAuth2Error) Error() string {
	return fmt.Sprintf("oauth2 error: %s (%s)", e.Description, e.Reason)
}

func GeneratePkceChallenge() PkceChallenge {
	codeVerifierBuf := make([]byte, stateBufSize)
	rand.Read(codeVerifierBuf)
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierBuf)
	codeChallengeHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeHash[:])
	return PkceChallenge{Verifier: codeVerifier, Challenge: codeChallenge}
}

func GenerateState() string {
	stateBuf := make([]byte, stateBufSize)
	rand.Read(stateBuf)
	return base64.URLEncoding.EncodeToString(stateBuf)
}

type PkceChallenge struct {
	Challenge string
	Verifier  string
}

var ErrNoPortsAvailable = errors.New("no ports available")

// findFirstFreePort will attempt to open a network listener for each port in turn, and return the first one that succeeded.
//
// If none succeed, ErrNoPortsAvailable is returned.
//
// This is useful for supporting OIDC servers that do not allow for ephemeral ports to be used in the loopback address, like Okta.
func findFirstFreePort(ctx context.Context, broadcastAddr string, ports []string) (net.Listener, error) {
	var lc net.ListenConfig
	for _, port := range ports {
		addr := net.JoinHostPort(broadcastAddr, port)
		slog.Debug("opening connection", slog.String("addr", addr))
		sock, err := lc.Listen(ctx, "tcp4", addr)
		if err == nil {
			slog.Debug("listening", slog.String("addr", addr))
			return sock, nil
		} else {
			slog.Debug("could not listen, trying a different addr", slog.String("addr", addr), slog.String("error", err.Error()))
		}
	}

	return nil, ErrNoPortsAvailable
}

// ListenAnyPort is a function that can be passed to RedirectionFlowHandler that will attempt to listen to exactly one of the ports in the supplied array.
//
// This function does not guarantee it will try ports in the order they are supplied, but it will return either a listener bound to exactly one of the ports, or the error ErrNoPortsAvailable.
func ListenAnyPort(broadcastAddr string, ports []string) func(ctx context.Context) (net.Listener, error) {
	return func(ctx context.Context) (net.Listener, error) {
		return findFirstFreePort(ctx, broadcastAddr, ports)
	}
}

func listenFixedPort(ctx context.Context) (net.Listener, error) {
	var lc net.ListenConfig
	sock, err := lc.Listen(ctx, "tcp4", net.JoinHostPort("0.0.0.0", "57468"))
	return sock, err
}

type RedirectionFlowHandler struct {
	Config       *oauth2.Config
	OnDisplayURL func(url string) error

	// Listen is a function that can be provided to override how the redirection flow handler opens a network socket.
	// If this is not specified, the handler will attempt to create a connection that listens to 0.0.0.0:57468 on IPv4.
	Listen func(ctx context.Context) (net.Listener, error)
}

func (r RedirectionFlowHandler) HandlePendingSession(ctx context.Context, challenge PkceChallenge, state string) (*oauth2.Token, error) {
	if r.OnDisplayURL == nil {
		r.OnDisplayURL = printURLToConsole
	}

	if r.Listen == nil {
		r.Listen = listenFixedPort
	}

	sock, err := r.Listen(ctx)
	if err != nil {
		return nil, err
	}
	defer sock.Close()

	_, port, err := net.SplitHostPort(sock.Addr().String())
	if err != nil {
		// Failed to split the host and port. We need the port to continue, so bail
		return nil, err
	}

	r.Config.RedirectURL = fmt.Sprintf("http://%s", net.JoinHostPort("localhost", port))
	url := r.Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", challenge.Challenge),
	)

	callbackHandler, ch, cancel := OAuth2CallbackHandler()
	// TODO: This error probably should not be ignored if it is not http.ErrServerClosed
	go http.Serve(sock, callbackHandler)
	defer cancel()

	if err := r.OnDisplayURL(url); err != nil {
		// This is unlikely to ever happen
		return nil, fmt.Errorf("failed to display link: %w", err)
	}

	select {
	case info := <-ch:
		code, err := info.Verify(state)
		if err != nil {
			return nil, fmt.Errorf("failed to get authorization code: %w", err)
		}
		return r.Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", challenge.Verifier))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type TokenExchange struct {
	ClientID           string
	ActorToken         string
	ActorTokenType     TokenType
	SubjectToken       string
	SubjectTokenType   TokenType
	GrantType          GrantType
	RequestedTokenType TokenType
	Audience           string
}

func (r TokenExchange) NewRequest(ctx context.Context, config *oauth2.Config) (*http.Request, error) {
	// https://datatracker.ietf.org/doc/html/rfc8693
	data := url.Values{
		"client_id":            {r.ClientID},
		"actor_token":          {r.ActorToken},
		"actor_token_type":     {string(r.ActorTokenType)},
		"subject_token":        {r.SubjectToken},
		"subject_token_type":   {string(r.SubjectTokenType)},
		"grant_type":           {string(r.GrantType)},
		"requested_token_type": {string(r.RequestedTokenType)},
		"audience":             {r.Audience},
	}
	body := strings.NewReader(data.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Endpoint.TokenURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

func (r TokenExchange) ProcessResponse(resp *http.Response) (*oauth2.Token, error) {
	if resp.StatusCode != http.StatusOK {
		// We've not been able to replicate this, but it does happen that sometimes Okta returns a non-200
		// response code and a body that does not contain an OAuth2 token. This causes KeyConjurer to submit
		// a blank oauth2 token to the next endpoint in the chain, resulting in a cryptic
		// "unable to parse SAML assertion" error.
		//
		// So, we will just assume that in any instance this returns a non-200 code that the user is unauthorized
		return nil, ErrUnauthorized
	}
	var tok oauth2.Token
	return &tok, json.NewDecoder(resp.Body).Decode(&tok)
}

func (r TokenExchange) Execute(ctx context.Context, client *http.Client, cfg *oauth2.Config) (*oauth2.Token, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := r.NewRequest(ctx, cfg)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return r.ProcessResponse(resp)
}

func makeOktaApplicationURN(applicationID string) string {
	return fmt.Sprintf("urn:okta:apps:%s", applicationID)
}

func ExchangeAccessTokenForWebSSOToken(ctx context.Context, client *http.Client, oauthCfg *oauth2.Config, token *TokenSet, applicationID string) (*oauth2.Token, error) {
	tex := TokenExchange{
		ClientID:           oauthCfg.ClientID,
		ActorToken:         token.AccessToken,
		ActorTokenType:     TokenTypeAccessToken,
		SubjectToken:       token.IDToken,
		SubjectTokenType:   TokenTypeIDToken,
		GrantType:          GrantTypeTokenExchange,
		RequestedTokenType: TokenTypeOktaWebSSOToken,
		Audience:           makeOktaApplicationURN(applicationID),
	}

	return tex.Execute(ctx, client, oauthCfg)
}

// TODO: This is actually an Okta-specific API
func ExchangeWebSSOTokenForSAMLAssertion(ctx context.Context, client *http.Client, issuer string, token *oauth2.Token) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}

	data := url.Values{"token": {token.AccessToken}}
	uri := fmt.Sprintf("%s/login/token/sso?%s", issuer, data.Encode())
	req, _ := http.NewRequestWithContext(ctx, "GET", uri, nil)
	req.Header.Add("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusInternalServerError {
		return nil, errors.New("internal okta error occurred")
	}

	doc, _ := html.Parse(resp.Body)
	form, ok := FindFirstForm(doc)
	if !ok {
		return nil, ErrNoSAMLAssertion
	}

	saml, ok := form.Inputs["SAMLResponse"]
	if !ok {
		return nil, ErrNoSAMLAssertion
	}

	return []byte(saml), nil
}

func DiscoverConfigAndExchangeTokenForAssertion(ctx context.Context, client *http.Client, toks *TokenSet, oidcDomain, clientID, applicationID string) (*saml.Response, string, error) {
	oauthCfg, err := DiscoverOAuth2Config(ctx, oidcDomain, clientID)
	if err != nil {
		return nil, "", OktaError{Message: "could not discover oauth2 config", InnerError: err}
	}

	tok, err := ExchangeAccessTokenForWebSSOToken(ctx, client, oauthCfg, toks, applicationID)
	if err != nil {
		return nil, "", OktaError{Message: "error exchanging token - try logging in again by deleting ~/.keyconjurerrc", InnerError: err}
	}

	assertionBytes, err := ExchangeWebSSOTokenForSAMLAssertion(ctx, client, oidcDomain, tok)
	if err != nil {
		log.Printf("%#v", err)
		return nil, "", OktaError{Message: "failed to fetch SAML assertion", InnerError: err}
	}

	response, err := ParseBase64EncodedSAMLResponse(string(assertionBytes))
	if err != nil {
		return nil, "", OktaError{Message: "failed to parse SAML response", InnerError: err}
	}

	return response, string(assertionBytes), nil
}
