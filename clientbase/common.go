package clientbase

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/rancher/norman/types"
)

const (
	SELF       = "self"
	COLLECTION = "collection"
)

var (
	Debug = false
)

type APIBaseClientInterface interface {
	Websocket(url string, headers map[string][]string) (*websocket.Conn, *http.Response, error)
	List(schemaType string, opts *types.ListOpts, respObject interface{}) error
	Post(url string, createObj interface{}, respObject interface{}) error
	GetLink(resource types.Resource, link string, respObject interface{}) error
	Create(schemaType string, createObj interface{}, respObject interface{}) error
	Update(schemaType string, existing *types.Resource, updates interface{}, respObject interface{}) error
	Replace(schemaType string, existing *types.Resource, updates interface{}, respObject interface{}) error
	ByID(schemaType string, id string, respObject interface{}) error
	Delete(existing *types.Resource) error
	Reload(existing *types.Resource, output interface{}) error
	Action(schemaType string, action string, existing *types.Resource, inputObject, respObject interface{}) error
}

type APIBaseClient struct {
	Ops   *APIOperations
	Opts  *ClientOpts
	Types map[string]types.Schema
}

type ClientOpts struct {
	URL        string
	AccessKey  string
	SecretKey  string
	TokenKey   string
	Timeout    time.Duration
	HTTPClient *http.Client
	WSDialer   *websocket.Dialer
	CACerts    string
	Insecure   bool
	ProxyURL   string
}

func (c *ClientOpts) getAuthHeader() string {
	if c.TokenKey != "" {
		return "Bearer " + c.TokenKey
	}
	if c.AccessKey != "" && c.SecretKey != "" {
		s := c.AccessKey + ":" + c.SecretKey
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
	}
	return ""
}

type APIError struct {
	StatusCode int
	URL        string
	Msg        string
	Status     string
	Body       string
}

func (e *APIError) Error() string {
	return e.Msg
}

func IsNotFound(err error) bool {
	apiError, ok := err.(*APIError)
	if !ok {
		return false
	}

	return apiError.StatusCode == http.StatusNotFound
}

func NewAPIError(resp *http.Response, url string) *APIError {
	apiError, _ := newAPIError(resp, url)
	return apiError
}

func newAPIError(resp *http.Response, url string) (*APIError, error) {
	contents, err := io.ReadAll(resp.Body)
	var body string
	if err != nil {
		body = "Unreadable body."
	} else {
		body = string(contents)
	}

	data := map[string]interface{}{}
	if json.Unmarshal(contents, &data) == nil {
		delete(data, "id")
		delete(data, "links")
		delete(data, "actions")
		delete(data, "type")
		delete(data, "status")
		buf := &bytes.Buffer{}
		for k, v := range data {
			if v == nil {
				continue
			}
			if buf.Len() > 0 {
				buf.WriteString(", ")
			}
			fmt.Fprintf(buf, "%s=%v", k, v)
		}
		body = buf.String()
	}
	formattedMsg := fmt.Sprintf("Bad response statusCode [%d]. Status [%s]. Body: [%s] from [%s]",
		resp.StatusCode, resp.Status, body, url)
	return &APIError{
		URL:        url,
		Msg:        formattedMsg,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Body:       body,
	}, err
}

// contextError retains the original cause when cancellation is observed at a boundary.
func contextError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		if err != nil {
			return fmt.Errorf("%w: %w", err, ctx.Err())
		}
		return ctx.Err()
	}
	return err
}

func responseError(ctx context.Context, resp *http.Response, url string, contextual bool) error {
	apiError, bodyErr := newAPIError(resp, url)
	if !contextual {
		return apiError
	}
	if bodyErr != nil {
		return contextError(ctx, fmt.Errorf("%w: %w", apiError, bodyErr))
	}
	return contextError(ctx, apiError)
}

func contains(array []string, item string) bool {
	for _, check := range array {
		if check == item {
			return true
		}
	}

	return false
}

func appendFilters(urlString string, filters map[string]interface{}) (string, error) {
	if len(filters) == 0 {
		return urlString, nil
	}

	u, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	q := u.Query()
	for k, v := range filters {
		if l, ok := v.([]string); ok {
			for _, v := range l {
				q.Add(k, v)
			}
		} else {
			q.Add(k, fmt.Sprintf("%v", v))
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func NewAPIClient(opts *ClientOpts) (APIBaseClient, error) {
	return newAPIClient(context.Background(), opts, false)
}

// NewAPIClientContext discovers schemas using ctx without retaining it in the client.
// The caller must exclusively own opts and its HTTPClient during construction.
func NewAPIClientContext(ctx context.Context, opts *ClientOpts) (APIBaseClient, error) {
	return newAPIClient(ctx, opts, true)
}

func newAPIClient(ctx context.Context, opts *ClientOpts, contextual bool) (APIBaseClient, error) {

	result := APIBaseClient{
		Types: map[string]types.Schema{},
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{}
	}

	if opts.Timeout == 0 {
		opts.Timeout = time.Minute
	}

	client.Timeout = opts.Timeout

	var proxy func(*http.Request) (*url.URL, error)
	if opts.ProxyURL != "" {
		proxyURL, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return result, fmt.Errorf("invalid proxy address %q: %w", opts.ProxyURL, err)
		}
		proxy = http.ProxyURL(proxyURL)
	} else {
		proxy = http.ProxyFromEnvironment
	}

	if opts.CACerts != "" {
		if Debug {
			fmt.Println("Some CAcerts are provided.")
		}
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(opts.CACerts))
		if !ok {
			return result, errors.New("failed to parse CA certificates: no valid PEM certificates")
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
			Proxy: proxy,
		}
		client.Transport = tr
	}

	if opts.Insecure {
		if Debug {
			fmt.Println("Insecure TLS set.")
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.Insecure,
			},
			Proxy: proxy,
		}
		client.Transport = tr
	}

	if !(opts.Insecure) && (opts.CACerts == "") {
		if Debug {
			fmt.Println("Insecure TLS not set and no CAcerts is provided.")
		}
		tr := &http.Transport{
			Proxy: proxy,
		}
		client.Transport = tr
	}

	published := false
	defer func() {
		if !published {
			client.CloseIdleConnections()
		}
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", opts.URL, nil)
	if err != nil {
		return result, contextError(ctx, err)
	}
	req.Header.Add("Authorization", opts.getAuthHeader())

	resp, err := client.Do(req)
	if err != nil {
		return result, contextError(ctx, err)
	}
	defer func(closer io.Closer) {
		_ = closer.Close()
	}(resp.Body)

	if resp.StatusCode != 200 {
		return result, responseError(ctx, resp, opts.URL, contextual)
	}

	schemasURLs := resp.Header.Get("X-API-Schemas")
	if len(schemasURLs) == 0 {
		return result, contextError(ctx, errors.New("Failed to find schema at ["+opts.URL+"]"))
	}

	if schemasURLs != opts.URL {
		req, err = http.NewRequestWithContext(ctx, "GET", schemasURLs, nil)
		if err != nil {
			return result, contextError(ctx, err)
		}
		req.Header.Add("Authorization", opts.getAuthHeader())

		if Debug {
			fmt.Println("GET " + req.URL.String())
		}

		resp, err = client.Do(req)
		if err != nil {
			return result, contextError(ctx, err)
		}
		defer func(closer io.Closer) {
			_ = closer.Close()
		}(resp.Body)

		if resp.StatusCode != 200 {
			return result, responseError(ctx, resp, schemasURLs, contextual)
		}
	}

	var schemas types.SchemaCollection
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, contextError(ctx, err)
	}

	if Debug {
		fmt.Println("Response <= " + string(bytes))
	}

	err = json.Unmarshal(bytes, &schemas)
	if err != nil {
		return result, contextError(ctx, err)
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	for _, schema := range schemas.Data {
		result.Types[schema.ID] = schema
	}

	result.Opts = opts
	result.Ops = &APIOperations{
		Opts:   opts,
		Client: client,
		Dialer: &websocket.Dialer{HandshakeTimeout: 10 * time.Second},
		Types:  result.Types,
	}

	if result.Opts.WSDialer != nil {
		result.Ops.Dialer = result.Opts.WSDialer
	}

	ht, ok := client.Transport.(*http.Transport)
	if ok {
		result.Ops.Dialer.TLSClientConfig = ht.TLSClientConfig
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}
	published = true
	return result, nil
}

func NewListOpts() *types.ListOpts {
	return &types.ListOpts{
		Filters: map[string]interface{}{},
	}
}

func (a *APIBaseClient) Websocket(url string, headers map[string][]string) (*websocket.Conn, *http.Response, error) {
	httpHeaders := http.Header{}
	for k, v := range httpHeaders {
		httpHeaders[k] = v
	}

	if a.Opts != nil {
		httpHeaders.Add("Authorization", a.Opts.getAuthHeader())
	}

	if Debug {
		fmt.Println("WS " + url)
	}

	return a.Ops.Dialer.Dial(url, http.Header(httpHeaders))
}

func (a *APIBaseClient) List(schemaType string, opts *types.ListOpts, respObject interface{}) error {
	return a.Ops.DoList(schemaType, opts, respObject)
}

func (a *APIBaseClient) Post(url string, createObj interface{}, respObject interface{}) error {
	return a.Ops.DoModify("POST", url, createObj, respObject)
}

func (a *APIBaseClient) GetLink(resource types.Resource, link string, respObject interface{}) error {
	url := resource.Links[link]
	if url == "" {
		return fmt.Errorf("failed to find link: %s", link)
	}

	return a.Ops.DoGet(url, &types.ListOpts{}, respObject)
}

func (a *APIBaseClient) Create(schemaType string, createObj interface{}, respObject interface{}) error {
	return a.Ops.DoCreate(schemaType, createObj, respObject)
}

func (a *APIBaseClient) Update(schemaType string, existing *types.Resource, updates interface{}, respObject interface{}) error {
	return a.Ops.DoUpdate(schemaType, existing, updates, respObject)
}

func (a *APIBaseClient) Replace(schemaType string, existing *types.Resource, updates interface{}, respObject interface{}) error {
	return a.Ops.DoReplace(schemaType, existing, updates, respObject)
}

func (a *APIBaseClient) ByID(schemaType string, id string, respObject interface{}) error {
	return a.Ops.DoByID(schemaType, id, respObject)
}

func (a *APIBaseClient) Delete(existing *types.Resource) error {
	if existing == nil {
		return nil
	}
	return a.Ops.DoResourceDelete(existing.Type, existing)
}

func (a *APIBaseClient) Reload(existing *types.Resource, output interface{}) error {
	selfURL, ok := existing.Links[SELF]
	if !ok {
		return fmt.Errorf("failed to find self URL of [%v]", existing)
	}

	return a.Ops.DoGet(selfURL, NewListOpts(), output)
}

func (a *APIBaseClient) Action(schemaType string, action string,
	existing *types.Resource, inputObject, respObject interface{}) error {
	return a.Ops.DoAction(schemaType, action, existing, inputObject, respObject)
}

func init() {
	Debug = os.Getenv("RANCHER_CLIENT_DEBUG") == "true"
	if Debug {
		fmt.Println("Rancher client debug on")
	}
}
