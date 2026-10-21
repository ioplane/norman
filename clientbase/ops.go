package clientbase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"github.com/rancher/norman/types"
)

type APIOperations struct {
	Opts   *ClientOpts
	Types  map[string]types.Schema
	Client *http.Client
	Dialer *websocket.Dialer
}

func (a *APIOperations) SetupRequest(req *http.Request) {
	req.Header.Add("Authorization", a.Opts.getAuthHeader())
}

func (a *APIOperations) DoDelete(url string) error {
	return a.doDelete(context.Background(), url, false)
}

func (a *APIOperations) doDelete(ctx context.Context, url string, contextual bool) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return contextError(ctx, err)
	}

	a.SetupRequest(req)

	resp, err := a.Client.Do(req)
	if err != nil {
		return contextError(ctx, err)
	}
	defer func() {
		if !contextual {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 300 {
		return responseError(ctx, resp, url, contextual)
	}
	if contextual {
		_, err := io.Copy(io.Discard, resp.Body)
		return contextError(ctx, err)
	}

	return nil
}

func (a *APIOperations) DoGet(url string, opts *types.ListOpts, respObject interface{}) error {
	return a.doGet(context.Background(), url, opts, respObject, false)
}

// DoGetContext reads a resource using only this request's context.
func (a *APIOperations) DoGetContext(ctx context.Context, url string, opts *types.ListOpts, out interface{}) error {
	return a.doGet(ctx, url, opts, out, true)
}

func (a *APIOperations) doGet(ctx context.Context, url string, opts *types.ListOpts, respObject interface{}, contextual bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts == nil {
		opts = NewListOpts()
	}
	url, err := appendFilters(url, opts.Filters)
	if err != nil {
		return contextError(ctx, err)
	}

	if Debug {
		fmt.Println("GET " + url)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return contextError(ctx, err)
	}

	a.SetupRequest(req)

	resp, err := a.Client.Do(req)
	if err != nil {
		return contextError(ctx, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		return responseError(ctx, resp, url, contextual)
	}

	byteContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return contextError(ctx, err)
	}

	if Debug {
		fmt.Println("Response <= " + string(byteContent))
	}

	if err := json.Unmarshal(byteContent, respObject); err != nil {
		return contextError(ctx, errors.Wrap(err, fmt.Sprintf("Failed to parse: %s", byteContent)))
	}

	return ctx.Err()
}

func (a *APIOperations) DoList(schemaType string, opts *types.ListOpts, respObject interface{}) error {
	schema, ok := a.Types[schemaType]
	if !ok {
		return errors.New("Unknown schema type [" + schemaType + "]")
	}

	if !contains(schema.CollectionMethods, "GET") {
		return errors.New("Resource type [" + schemaType + "] is not listable")
	}

	collectionURL, ok := schema.Links["collection"]
	if !ok {
		return errors.New("Resource type [" + schemaType + "] does not have a collection URL")
	}

	return a.DoGet(collectionURL, opts, respObject)
}

func (a *APIOperations) DoNext(nextURL string, respObject interface{}) error {
	return a.DoGet(nextURL, nil, respObject)
}

func (a *APIOperations) DoModify(method string, url string, createObj interface{}, respObject interface{}) error {
	return a.doModify(context.Background(), method, url, createObj, respObject, false)
}

func (a *APIOperations) doModify(ctx context.Context, method string, url string, createObj interface{}, respObject interface{}, contextual bool) error {
	if createObj == nil {
		createObj = map[string]string{}
	}
	if respObject == nil {
		respObject = &map[string]interface{}{}
	}
	bodyContent, err := json.Marshal(createObj)
	if err != nil {
		return contextError(ctx, err)
	}

	if Debug {
		fmt.Println(method + " " + url)
		fmt.Println("Request => " + string(bodyContent))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(bodyContent))
	if err != nil {
		return contextError(ctx, err)
	}

	a.SetupRequest(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.Client.Do(req)
	if err != nil {
		return contextError(ctx, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 300 {
		return responseError(ctx, resp, url, contextual)
	}

	byteContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return contextError(ctx, err)
	}

	if len(byteContent) > 0 {
		if Debug {
			fmt.Println("Response <= " + string(byteContent))
		}
		return contextError(ctx, json.Unmarshal(byteContent, respObject))
	}

	return ctx.Err()
}

func (a *APIOperations) DoCreate(schemaType string, createObj interface{}, respObject interface{}) error {
	return a.doCreate(context.Background(), schemaType, createObj, respObject, false)
}

// DoCreateContext creates a resource without retrying a canceled write.
func (a *APIOperations) DoCreateContext(ctx context.Context, schemaType string, createObj, respObject any) error {
	return a.doCreate(ctx, schemaType, createObj, respObject, true)
}

func (a *APIOperations) doCreate(ctx context.Context, schemaType string, createObj interface{}, respObject interface{}, contextual bool) error {
	if createObj == nil {
		createObj = map[string]string{}
	}
	if respObject == nil {
		respObject = &map[string]interface{}{}
	}
	schema, ok := a.Types[schemaType]
	if !ok {
		return errors.New("Unknown schema type [" + schemaType + "]")
	}

	if !contains(schema.CollectionMethods, "POST") {
		return errors.New("Resource type [" + schemaType + "] is not creatable")
	}

	var collectionURL string
	collectionURL, ok = schema.Links[COLLECTION]
	if !ok {
		// return errors.New("Failed to find collection URL for [" + schemaType + "]")
		// This is a hack to address https://github.com/rancher/cattle/issues/254
		re := regexp.MustCompile("schemas.*")
		collectionURL = re.ReplaceAllString(schema.Links[SELF], schema.PluralName)
	}

	return a.doModify(ctx, "POST", collectionURL, createObj, respObject, contextual)
}

func (a *APIOperations) DoReplace(schemaType string, existing *types.Resource, updates interface{}, respObject interface{}) error {
	return a.doUpdate(context.Background(), schemaType, true, existing, updates, respObject, false)
}

func (a *APIOperations) DoUpdate(schemaType string, existing *types.Resource, updates interface{}, respObject interface{}) error {
	return a.doUpdate(context.Background(), schemaType, false, existing, updates, respObject, false)
}

// DoUpdateContext updates a resource using only this operation's context.
func (a *APIOperations) DoUpdateContext(ctx context.Context, schemaType string, existing *types.Resource, updates, respObject any) error {
	return a.doUpdate(ctx, schemaType, false, existing, updates, respObject, true)
}

func (a *APIOperations) doUpdate(ctx context.Context, schemaType string, replace bool, existing *types.Resource, updates interface{}, respObject interface{}, contextual bool) error {
	if existing == nil {
		return errors.New("Existing object is nil")
	}

	selfURL, ok := existing.Links[SELF]
	if !ok {
		return fmt.Errorf("failed to find self URL of [%v]", existing)
	}

	if replace {
		u, err := url.Parse(selfURL)
		if err != nil {
			return fmt.Errorf("failed to parse url %s: %v", selfURL, err)
		}
		q := u.Query()
		q.Set("_replace", "true")
		u.RawQuery = q.Encode()
		selfURL = u.String()
	}

	if updates == nil {
		updates = map[string]string{}
	}

	if respObject == nil {
		respObject = &map[string]interface{}{}
	}

	schema, ok := a.Types[schemaType]
	if !ok {
		return errors.New("Unknown schema type [" + schemaType + "]")
	}

	if !contains(schema.ResourceMethods, "PUT") {
		return errors.New("Resource type [" + schemaType + "] is not updatable")
	}

	return a.doModify(ctx, "PUT", selfURL, updates, respObject, contextual)
}

func (a *APIOperations) DoByID(schemaType string, id string, respObject interface{}) error {
	return a.doByID(context.Background(), schemaType, id, respObject, false)
}

// DoByIDContext preserves schema lookup rules and cancels the resulting GET with ctx.
func (a *APIOperations) DoByIDContext(ctx context.Context, schemaType, id string, out interface{}) error {
	return a.doByID(ctx, schemaType, id, out, true)
}

func (a *APIOperations) doByID(ctx context.Context, schemaType, id string, respObject interface{}, contextual bool) error {
	schema, ok := a.Types[schemaType]
	if !ok {
		return errors.New("Unknown schema type [" + schemaType + "]")
	}

	if !contains(schema.ResourceMethods, "GET") {
		return errors.New("Resource type [" + schemaType + "] can not be looked up by ID")
	}

	collectionURL, ok := schema.Links[COLLECTION]
	if !ok {
		return errors.New("Failed to find collection URL for [" + schemaType + "]")
	}

	return a.doGet(ctx, collectionURL+"/"+id, nil, respObject, contextual)
}

func (a *APIOperations) DoResourceDelete(schemaType string, existing *types.Resource) error {
	return a.doResourceDelete(context.Background(), schemaType, existing, false)
}

// DoResourceDeleteContext deletes a resource without retrying an uncertain outcome.
func (a *APIOperations) DoResourceDeleteContext(ctx context.Context, schemaType string, existing *types.Resource) error {
	if existing == nil {
		return fmt.Errorf("delete %s: existing object is nil", schemaType)
	}
	return a.doResourceDelete(ctx, schemaType, existing, true)
}

func (a *APIOperations) doResourceDelete(ctx context.Context, schemaType string, existing *types.Resource, contextual bool) error {
	schema, ok := a.Types[schemaType]
	if !ok {
		return errors.New("Unknown schema type [" + schemaType + "]")
	}

	if !contains(schema.ResourceMethods, "DELETE") {
		return errors.New("Resource type [" + schemaType + "] can not be deleted")
	}

	selfURL, ok := existing.Links[SELF]
	if !ok {
		return fmt.Errorf("failed to find self URL of [%v]", existing)
	}

	return a.doDelete(ctx, selfURL, contextual)
}

func (a *APIOperations) DoAction(schemaType string, action string,
	existing *types.Resource, inputObject, respObject interface{}) error {

	if existing == nil {
		return errors.New("Existing object is nil")
	}

	actionURL, ok := existing.Actions[action]
	if !ok {
		return fmt.Errorf("action [%v] not available on [%v]", action, existing)
	}

	return a.doAction(schemaType, action, actionURL, inputObject, respObject)
}

func (a *APIOperations) DoCollectionAction(schemaType string, action string,
	existing *types.Collection, inputObject, respObject interface{}) error {

	if existing == nil {
		return errors.New("Existing object is nil")
	}

	actionURL, ok := existing.Actions[action]
	if !ok {
		return fmt.Errorf("action [%v] not available on [%v]", action, existing)
	}

	return a.doAction(schemaType, action, actionURL, inputObject, respObject)
}

func (a *APIOperations) doAction(
	schemaType string,
	action string,
	actionURL string,
	inputObject interface{},
	respObject interface{},
) error {
	_, ok := a.Types[schemaType]
	if !ok {
		return errors.New("Unknown schema type [" + schemaType + "]")
	}

	var input io.Reader

	if Debug {
		fmt.Println("POST " + actionURL)
	}

	if inputObject != nil {
		bodyContent, err := json.Marshal(inputObject)
		if err != nil {
			return err
		}
		if Debug {
			fmt.Println("Request => " + string(bodyContent))
		}
		input = bytes.NewBuffer(bodyContent)
	}

	req, err := http.NewRequest("POST", actionURL, input)
	if err != nil {
		return err
	}

	a.SetupRequest(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "0")

	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 300 {
		return NewAPIError(resp, actionURL)
	}

	byteContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if Debug {
		fmt.Println("Response <= " + string(byteContent))
	}

	if nil != respObject {
		return json.Unmarshal(byteContent, respObject)
	}
	return nil
}
