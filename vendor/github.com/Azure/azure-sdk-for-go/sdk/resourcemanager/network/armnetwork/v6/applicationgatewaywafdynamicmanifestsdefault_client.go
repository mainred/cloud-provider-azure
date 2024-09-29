//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armnetwork

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// ApplicationGatewayWafDynamicManifestsDefaultClient contains the methods for the ApplicationGatewayWafDynamicManifestsDefault group.
// Don't use this type directly, use NewApplicationGatewayWafDynamicManifestsDefaultClient() instead.
type ApplicationGatewayWafDynamicManifestsDefaultClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewApplicationGatewayWafDynamicManifestsDefaultClient creates a new instance of ApplicationGatewayWafDynamicManifestsDefaultClient with the specified values.
//   - subscriptionID - The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription
//     ID forms part of the URI for every service call.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewApplicationGatewayWafDynamicManifestsDefaultClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*ApplicationGatewayWafDynamicManifestsDefaultClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &ApplicationGatewayWafDynamicManifestsDefaultClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// Get - Gets the regional application gateway waf manifest.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-03-01
//   - location - The region where the nrp are located at.
//   - options - ApplicationGatewayWafDynamicManifestsDefaultClientGetOptions contains the optional parameters for the ApplicationGatewayWafDynamicManifestsDefaultClient.Get
//     method.
func (client *ApplicationGatewayWafDynamicManifestsDefaultClient) Get(ctx context.Context, location string, options *ApplicationGatewayWafDynamicManifestsDefaultClientGetOptions) (ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse, error) {
	var err error
	const operationName = "ApplicationGatewayWafDynamicManifestsDefaultClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, location, options)
	if err != nil {
		return ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *ApplicationGatewayWafDynamicManifestsDefaultClient) getCreateRequest(ctx context.Context, location string, options *ApplicationGatewayWafDynamicManifestsDefaultClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Network/locations/{location}/applicationGatewayWafDynamicManifests/dafault"
	if location == "" {
		return nil, errors.New("parameter location cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{location}", url.PathEscape(location))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-03-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *ApplicationGatewayWafDynamicManifestsDefaultClient) getHandleResponse(resp *http.Response) (ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse, error) {
	result := ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.ApplicationGatewayWafDynamicManifestResult); err != nil {
		return ApplicationGatewayWafDynamicManifestsDefaultClientGetResponse{}, err
	}
	return result, nil
}