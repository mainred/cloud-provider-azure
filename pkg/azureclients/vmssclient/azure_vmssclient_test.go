/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vmssclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2022-08-01/compute"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/stretchr/testify/assert"

	"go.uber.org/mock/gomock"

	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/utils/ptr"

	azclients "sigs.k8s.io/cloud-provider-azure/pkg/azureclients"
	"sigs.k8s.io/cloud-provider-azure/pkg/azureclients/armclient"
	"sigs.k8s.io/cloud-provider-azure/pkg/azureclients/armclient/mockarmclient"
	"sigs.k8s.io/cloud-provider-azure/pkg/consts"
	"sigs.k8s.io/cloud-provider-azure/pkg/retry"
)

const (
	testResourceID     = "/subscriptions/subscriptionID/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1"
	testResourcePrefix = "/subscriptions/subscriptionID/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets"
)

func TestNew(t *testing.T) {
	config := &azclients.ClientConfig{
		SubscriptionID:          "sub",
		ResourceManagerEndpoint: "endpoint",
		Location:                "eastus",
		RateLimitConfig: &azclients.RateLimitConfig{
			CloudProviderRateLimit:            true,
			CloudProviderRateLimitQPS:         0.5,
			CloudProviderRateLimitBucket:      1,
			CloudProviderRateLimitQPSWrite:    0.5,
			CloudProviderRateLimitBucketWrite: 1,
		},
		Backoff: &retry.Backoff{Steps: 1},
	}

	vmssClient := New(config)
	assert.Equal(t, "sub", vmssClient.subscriptionID)
	assert.NotEmpty(t, vmssClient.rateLimiterReader)
	assert.NotEmpty(t, vmssClient.rateLimiterWriter)
}

func TestNewAzureStack(t *testing.T) {
	config := &azclients.ClientConfig{
		CloudName:               "AZURESTACKCLOUD",
		SubscriptionID:          "sub",
		ResourceManagerEndpoint: "endpoint",
		Location:                "eastus",
		RateLimitConfig: &azclients.RateLimitConfig{
			CloudProviderRateLimit:            true,
			CloudProviderRateLimitQPS:         0.5,
			CloudProviderRateLimitBucket:      1,
			CloudProviderRateLimitQPSWrite:    0.5,
			CloudProviderRateLimitBucketWrite: 1,
		},
		Backoff: &retry.Backoff{Steps: 1},
	}

	vmssClient := New(config)
	assert.Equal(t, "AZURESTACKCLOUD", vmssClient.cloudName)
	assert.Equal(t, "sub", vmssClient.subscriptionID)
}

func TestGet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResource(gomock.Any(), testResourceID).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	expected := VirtualMachineScaleSet{VirtualMachineScaleSet: compute.VirtualMachineScaleSet{Response: autorest.Response{Response: response}}}
	vmssClient := getTestVMSSClient(armClient)
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1")
	assert.Equal(t, expected, result)
	assert.Nil(t, rerr)
}

func TestGetNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssGetErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "read", "VMSSGet"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithNeverRateLimiter(armClient)
	expected := VirtualMachineScaleSet{}
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1")
	assert.Equal(t, expected, result)
	assert.Equal(t, vmssGetErr, rerr)
}

func TestGetRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssGetErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSGet", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithRetryAfterReader(armClient)
	expected := VirtualMachineScaleSet{}
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1")
	assert.Equal(t, expected, result)
	assert.Equal(t, vmssGetErr, rerr)
}

func TestGetNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResource(gomock.Any(), testResourceID).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	expectedVMSS := VirtualMachineScaleSet{VirtualMachineScaleSet: compute.VirtualMachineScaleSet{Response: autorest.Response{}}}
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1")
	assert.Equal(t, expectedVMSS, result)
	assert.NotNil(t, rerr)
	assert.Equal(t, http.StatusNotFound, rerr.HTTPStatusCode)
}

func TestGetInternalError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResource(gomock.Any(), testResourceID).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	expectedVMSS := VirtualMachineScaleSet{VirtualMachineScaleSet: compute.VirtualMachineScaleSet{Response: autorest.Response{}}}
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1")
	assert.Equal(t, expectedVMSS, result)
	assert.NotNil(t, rerr)
	assert.Equal(t, http.StatusInternalServerError, rerr.HTTPStatusCode)
}

func TestGetThrottle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	throttleErr := &retry.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		RawError:       fmt.Errorf("error"),
		Retriable:      true,
		RetryAfter:     time.Unix(100, 0),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResource(gomock.Any(), testResourceID).Return(response, throttleErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1")
	assert.Empty(t, result)
	assert.Equal(t, throttleErr, rerr)
}

func TestList(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssList := []VirtualMachineScaleSet{getTestVMSS("vmss1"), getTestVMSS("vmss2"), getTestVMSS("vmss3")}
	responseBody, err := json.Marshal(VirtualMachineScaleSetListResult{Value: &vmssList})
	assert.NoError(t, err)
	armClient.EXPECT().GetResource(gomock.Any(), testResourcePrefix).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.Nil(t, rerr)
	assert.Equal(t, 3, len(result))
}

func TestListNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResource(gomock.Any(), testResourcePrefix).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	expected := []VirtualMachineScaleSet{}
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.Equal(t, expected, result)
	assert.NotNil(t, rerr)
	assert.Equal(t, http.StatusNotFound, rerr.HTTPStatusCode)
}

func TestListInternalError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResource(gomock.Any(), testResourcePrefix).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	expected := []VirtualMachineScaleSet{}
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.Equal(t, expected, result)
	assert.NotNil(t, rerr)
	assert.Equal(t, http.StatusInternalServerError, rerr.HTTPStatusCode)
}

func TestListThrottle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	response := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	throttleErr := &retry.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		RawError:       fmt.Errorf("error"),
		Retriable:      true,
		RetryAfter:     time.Unix(100, 0),
	}
	armClient.EXPECT().GetResource(gomock.Any(), testResourcePrefix).Return(response, throttleErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	vmssClient := getTestVMSSClient(armClient)
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.Empty(t, result)
	assert.NotNil(t, rerr)
	assert.Equal(t, throttleErr, rerr)
}

func TestListWithListResponderError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssList := []VirtualMachineScaleSet{getTestVMSS("vmss1"), getTestVMSS("vmss2"), getTestVMSS("vmss3")}
	responseBody, err := json.Marshal(VirtualMachineScaleSetListResult{Value: &vmssList})
	assert.NoError(t, err)
	armClient.EXPECT().GetResource(gomock.Any(), testResourcePrefix).Return(
		&http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	vmssClient := getTestVMSSClient(armClient)
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.NotNil(t, rerr)
	assert.Equal(t, 0, len(result))
}

func TestListWithNextPage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssList := []VirtualMachineScaleSet{getTestVMSS("vmss1"), getTestVMSS("vmss2"), getTestVMSS("vmss3")}
	partialResponse, err := json.Marshal(VirtualMachineScaleSetListResult{Value: &vmssList, NextLink: ptr.To("nextLink")})
	assert.NoError(t, err)
	pagedResponse, err := json.Marshal(VirtualMachineScaleSetListResult{Value: &vmssList})
	assert.NoError(t, err)
	armClient.EXPECT().PrepareGetRequest(gomock.Any(), gomock.Any()).Return(&http.Request{}, nil)
	armClient.EXPECT().Send(gomock.Any(), gomock.Any()).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(pagedResponse)),
		}, nil)
	armClient.EXPECT().GetResource(gomock.Any(), testResourcePrefix).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(partialResponse)),
		}, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(2)
	vmssClient := getTestVMSSClient(armClient)
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.Nil(t, rerr)
	assert.Equal(t, 6, len(result))
}

func TestListNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssListErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "read", "VMSSList"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithNeverRateLimiter(armClient)
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.Equal(t, 0, len(result))
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssListErr, rerr)
}

func TestListRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssListErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSList", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithRetryAfterReader(armClient)
	result, rerr := vmssClient.List(context.TODO(), "rg")
	assert.Equal(t, 0, len(result))
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssListErr, rerr)
}

func TestListNextResultsMultiPages(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name           string
		prepareErr     error
		sendErr        *retry.Error
		expectedErrMsg string
	}{
		{
			name:       "testlistNextResultsSuccessful",
			prepareErr: nil,
			sendErr:    nil,
		},
		{
			name:           "testPrepareGetRequestError",
			prepareErr:     fmt.Errorf("error"),
			expectedErrMsg: "Failure preparing next results request",
		},
		{
			name:           "testSendError",
			sendErr:        &retry.Error{RawError: fmt.Errorf("error")},
			expectedErrMsg: "Failure sending next results request",
		},
	}

	lastResult := VirtualMachineScaleSetListResult{
		NextLink: ptr.To("next"),
	}

	for _, test := range tests {
		armClient := mockarmclient.NewMockInterface(ctrl)
		req := &http.Request{
			Method: "GET",
		}
		armClient.EXPECT().PrepareGetRequest(gomock.Any(), gomock.Any()).Return(req, test.prepareErr)
		if test.prepareErr == nil {
			armClient.EXPECT().Send(gomock.Any(), req).Return(&http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"foo":"bar"}`))),
			}, test.sendErr)
			armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any())
		}

		vmssClient := getTestVMSSClient(armClient)
		result, err := vmssClient.listNextResults(context.TODO(), lastResult)
		if err != nil {
			detailedErr := &autorest.DetailedError{}
			assert.True(t, errors.As(err, detailedErr))
			assert.Equal(t, detailedErr.Message, test.expectedErrMsg)
		} else {
			assert.NoError(t, err)
		}

		if test.prepareErr != nil {
			assert.Empty(t, result)
		} else {
			assert.NotEmpty(t, result)
		}
	}
}

func TestListNextResultsMultiPagesWithListResponderError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tests := []struct {
		name       string
		prepareErr error
		sendErr    *retry.Error
	}{
		{
			name:       "testListResponderError",
			prepareErr: nil,
			sendErr:    nil,
		},
		{
			name:    "testSendError",
			sendErr: &retry.Error{RawError: fmt.Errorf("error")},
		},
	}

	lastResult := VirtualMachineScaleSetListResult{
		NextLink: ptr.To("next"),
	}

	for _, test := range tests {
		armClient := mockarmclient.NewMockInterface(ctrl)
		req := &http.Request{
			Method: "GET",
		}
		armClient.EXPECT().PrepareGetRequest(gomock.Any(), gomock.Any()).Return(req, test.prepareErr)
		if test.prepareErr == nil {
			armClient.EXPECT().Send(gomock.Any(), req).Return(&http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"foo":"bar"}`))),
			}, test.sendErr)
			armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any())
		}

		response := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewBuffer([]byte(`{"foo":"bar"}`))),
		}
		expected := VirtualMachineScaleSetListResult{}
		expected.Response = autorest.Response{Response: response}
		vmssClient := getTestVMSSClient(armClient)
		result, err := vmssClient.listNextResults(context.TODO(), lastResult)
		assert.Error(t, err)
		if test.sendErr != nil {
			assert.NotEqual(t, expected, result)
		} else {
			assert.Equal(t, expected, result)
		}
	}
}

func TestCreateOrUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmss := getTestVMSS("vmss1")
	armClient := mockarmclient.NewMockInterface(ctrl)
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	armClient.EXPECT().PutResource(gomock.Any(), ptr.Deref(vmss.ID, ""), vmss).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	rerr := vmssClient.CreateOrUpdate(context.TODO(), "rg", "vmss1", vmss, "")
	assert.Nil(t, rerr)
}

func TestCreateOrUpdateWithCreateOrUpdateResponderError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	vmss := getTestVMSS("vmss1")
	armClient := mockarmclient.NewMockInterface(ctrl)
	response := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	armClient.EXPECT().PutResource(gomock.Any(), ptr.Deref(vmss.ID, ""), vmss).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	rerr := vmssClient.CreateOrUpdate(context.TODO(), "rg", "vmss1", vmss, "")
	assert.NotNil(t, rerr)
}

func TestCreateOrUpdateNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssCreateOrUpdateErr := retry.GetRateLimitError(true, "VMSSCreateOrUpdate")

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithNeverRateLimiter(armClient)
	vmss := getTestVMSS("vmss1")
	rerr := vmssClient.CreateOrUpdate(context.TODO(), "rg", "vmss1", vmss, "")
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssCreateOrUpdateErr, rerr)
}

func TestCreateOrUpdateRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssCreateOrUpdateErr := retry.GetThrottlingError("VMSSCreateOrUpdate", "client throttled", getFutureTime())

	vmss := getTestVMSS("vmss1")
	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithRetryAfterReader(armClient)
	rerr := vmssClient.CreateOrUpdate(context.TODO(), "rg", "vmss1", vmss, "")
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssCreateOrUpdateErr, rerr)
}

func TestCreateOrUpdateThrottle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	throttleErr := &retry.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		RawError:       fmt.Errorf("error"),
		Retriable:      true,
		RetryAfter:     time.Unix(100, 0),
	}

	vmss := getTestVMSS("vmss1")
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResource(gomock.Any(), ptr.Deref(vmss.ID, ""), vmss).Return(response, throttleErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	rerr := vmssClient.CreateOrUpdate(context.TODO(), "rg", "vmss1", vmss, "")
	assert.NotNil(t, rerr)
	assert.Equal(t, throttleErr, rerr)
}

func TestCreateOrUpdateAsync(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmss := getTestVMSS("vmss1")
	armClient := mockarmclient.NewMockInterface(ctrl)
	future := &azure.Future{}

	armClient.EXPECT().PutResourceAsync(gomock.Any(), ptr.Deref(vmss.ID, ""), vmss).Return(future, nil).Times(1)
	vmssClient := getTestVMSSClient(armClient)
	_, rerr := vmssClient.CreateOrUpdateAsync(context.TODO(), "rg", "vmss1", vmss, "")
	assert.Nil(t, rerr)

	retryErr := &retry.Error{RawError: fmt.Errorf("error")}
	armClient.EXPECT().PutResourceAsync(gomock.Any(), ptr.Deref(vmss.ID, ""), vmss).Return(future, retryErr).Times(1)
	_, rerr = vmssClient.CreateOrUpdateAsync(context.TODO(), "rg", "vmss1", vmss, "")
	assert.Equal(t, retryErr, rerr)
}

func TestCreateOrUpdateAsyncNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssCreateOrUpdateAsyncErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "write", "VMSSCreateOrUpdateAsync"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithNeverRateLimiter(armClient)
	vmss := getTestVMSS("vmss1")
	_, rerr := vmssClient.CreateOrUpdateAsync(context.TODO(), "rg", "vmss1", vmss, "")
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssCreateOrUpdateAsyncErr, rerr)
}

func TestCreateOrUpdateAsyncRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssCreateOrUpdateAsyncErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSCreateOrUpdateAsync", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	vmss := getTestVMSS("vmss1")
	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithRetryAfterReader(armClient)
	_, rerr := vmssClient.CreateOrUpdateAsync(context.TODO(), "rg", "vmss1", vmss, "")
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssCreateOrUpdateAsyncErr, rerr)
}

func TestCreateOrUpdateAsyncThrottle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	throttleErr := &retry.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		RawError:       fmt.Errorf("error"),
		Retriable:      true,
		RetryAfter:     time.Unix(100, 0),
	}

	vmss := getTestVMSS("vmss1")
	future := &azure.Future{}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResourceAsync(gomock.Any(), ptr.Deref(vmss.ID, ""), vmss).Return(future, throttleErr).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	_, rerr := vmssClient.CreateOrUpdateAsync(context.TODO(), "rg", "vmss1", vmss, "")
	assert.NotNil(t, rerr)
	assert.Equal(t, throttleErr, rerr)
}

func TestWaitForAsyncOperationResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}

	armClient.EXPECT().WaitForAsyncOperationResult(gomock.Any(), &azure.Future{}, "VMSSWaitForAsyncOperationResult").Return(response, nil)
	vmssClient := getTestVMSSClient(armClient)
	_, err := vmssClient.WaitForAsyncOperationResult(context.TODO(), &azure.Future{}, "rgName", "req", "VMSSWaitForAsyncOperationResult")
	assert.NoError(t, err)
}

func TestDeleteInstances(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	r := getTestVMSS("vmss1")
	vmInstanceIDs := compute.VirtualMachineScaleSetVMInstanceRequiredIDs{
		InstanceIds: &[]string{"0", "1", "2"},
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Request:    &http.Request{Method: "POST"},
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PostResource(gomock.Any(), ptr.Deref(r.ID, ""), "delete", vmInstanceIDs, map[string]interface{}{}).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	armClient.EXPECT().WaitForAsyncOperationCompletion(gomock.Any(), gomock.Any(), "vmssclient.DeleteInstances").Return(nil).Times(1)

	client := getTestVMSSClient(armClient)
	rerr := client.DeleteInstances(context.TODO(), "rg", "vmss1", vmInstanceIDs)
	assert.Nil(t, rerr)
}

func TestDeleteInstancesNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmInstanceIDs := compute.VirtualMachineScaleSetVMInstanceRequiredIDs{
		InstanceIds: &[]string{"0", "1", "2"},
	}
	vmssDeleteInstancesErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "write", "VMSSDeleteInstances"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithNeverRateLimiter(armClient)
	rerr := vmssClient.DeleteInstances(context.TODO(), "rg", "vmss1", vmInstanceIDs)
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssDeleteInstancesErr, rerr)
}

func TestDeleteInstancesRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmInstanceIDs := compute.VirtualMachineScaleSetVMInstanceRequiredIDs{
		InstanceIds: &[]string{"0", "1", "2"},
	}
	vmssDeleteInstancesErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSDeleteInstances", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssClient := getTestVMSSClientWithRetryAfterReader(armClient)
	rerr := vmssClient.DeleteInstances(context.TODO(), "rg", "vmss1", vmInstanceIDs)
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssDeleteInstancesErr, rerr)
}

func TestDeleteInstancesThrottle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmss := getTestVMSS("vmss1")
	vmInstanceIDs := compute.VirtualMachineScaleSetVMInstanceRequiredIDs{
		InstanceIds: &[]string{"0", "1", "2"},
	}
	response := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	throttleErr := &retry.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		RawError:       fmt.Errorf("error"),
		Retriable:      true,
		RetryAfter:     time.Unix(100, 0),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PostResource(gomock.Any(), ptr.Deref(vmss.ID, ""), "delete", vmInstanceIDs, map[string]interface{}{}).Return(response, throttleErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	rerr := vmssClient.DeleteInstances(context.TODO(), "rg", "vmss1", vmInstanceIDs)
	assert.NotNil(t, rerr)
	assert.Equal(t, throttleErr, rerr)
}

func TestDeleteInstancesWaitError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmss := getTestVMSS("vmss1")
	vmInstanceIDs := compute.VirtualMachineScaleSetVMInstanceRequiredIDs{
		InstanceIds: &[]string{"0", "1", "2"},
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Request:    &http.Request{Method: "POST"},
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	err := fmt.Errorf("%s", string("Wait error"))
	vmssDeleteInstancesErr := &retry.Error{
		RawError:  err,
		Retriable: false,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PostResource(gomock.Any(), ptr.Deref(vmss.ID, ""), "delete", vmInstanceIDs, map[string]interface{}{}).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	armClient.EXPECT().WaitForAsyncOperationCompletion(gomock.Any(), gomock.Any(), "vmssclient.DeleteInstances").Return(err).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	rerr := vmssClient.DeleteInstances(context.TODO(), "rg", "vmss1", vmInstanceIDs)
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssDeleteInstancesErr, rerr)
}

func TestDeleteInstancesAsync(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmss := getTestVMSS("vmss1")
	vmInstanceIDs := compute.VirtualMachineScaleSetVMInstanceRequiredIDs{
		InstanceIds: &[]string{"0", "1", "2"},
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Request:    &http.Request{Method: "POST"},
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PostResource(gomock.Any(), ptr.Deref(vmss.ID, ""), "delete", vmInstanceIDs, gomock.Any()).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSClient(armClient)
	future, rerr := vmssClient.DeleteInstancesAsync(context.TODO(), "rg", "vmss1", vmInstanceIDs, false)
	assert.Nil(t, rerr)
	assert.Equal(t, future.Status(), "Succeeded")

	// with force delete
	armClient.EXPECT().PostResource(gomock.Any(), ptr.Deref(vmss.ID, ""), "delete", vmInstanceIDs, map[string]interface{}{"forceDeletion": true}).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	future, rerr = vmssClient.DeleteInstancesAsync(context.TODO(), "rg", "vmss1", vmInstanceIDs, true)
	assert.Nil(t, rerr)
	assert.Equal(t, future.Status(), "Succeeded")

	// on error
	retryErr := &retry.Error{RawError: fmt.Errorf("error")}
	armClient.EXPECT().PostResource(gomock.Any(), ptr.Deref(vmss.ID, ""), "delete", vmInstanceIDs, gomock.Any()).Return(&http.Response{StatusCode: http.StatusBadRequest}, retryErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	_, rerr = vmssClient.DeleteInstancesAsync(context.TODO(), "rg", "vmss1", vmInstanceIDs, false)
	assert.Equal(t, retryErr, rerr)
}

func getTestVMSS(name string) VirtualMachineScaleSet {
	return VirtualMachineScaleSet{
		VirtualMachineScaleSet: compute.VirtualMachineScaleSet{
			ID:       ptr.To("/subscriptions/subscriptionID/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1"),
			Name:     ptr.To(name),
			Location: ptr.To("eastus"),
			Sku: &compute.Sku{
				Name:     ptr.To("Standard"),
				Capacity: ptr.To(int64(3)),
			},
		},
	}
}

func getTestVMSSClient(armClient armclient.Interface) *Client {
	rateLimiterReader, rateLimiterWriter := azclients.NewRateLimiter(&azclients.RateLimitConfig{})
	return &Client{
		armClient:         armClient,
		subscriptionID:    "subscriptionID",
		rateLimiterReader: rateLimiterReader,
		rateLimiterWriter: rateLimiterWriter,
	}
}

func getTestVMSSClientWithNeverRateLimiter(armClient armclient.Interface) *Client {
	rateLimiterReader := flowcontrol.NewFakeNeverRateLimiter()
	rateLimiterWriter := flowcontrol.NewFakeNeverRateLimiter()
	return &Client{
		armClient:         armClient,
		subscriptionID:    "subscriptionID",
		rateLimiterReader: rateLimiterReader,
		rateLimiterWriter: rateLimiterWriter,
	}
}

func getTestVMSSClientWithRetryAfterReader(armClient armclient.Interface) *Client {
	rateLimiterReader := flowcontrol.NewFakeAlwaysRateLimiter()
	rateLimiterWriter := flowcontrol.NewFakeAlwaysRateLimiter()
	return &Client{
		armClient:         armClient,
		subscriptionID:    "subscriptionID",
		rateLimiterReader: rateLimiterReader,
		rateLimiterWriter: rateLimiterWriter,
		RetryAfterReader:  getFutureTime(),
		RetryAfterWriter:  getFutureTime(),
	}
}

func getFutureTime() time.Time {
	return time.Unix(3000000000, 0)
}

func getFakeVmssVM() VirtualMachineScaleSet {
	testLBBackendpoolID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"
	virtualMachineScaleSetNetworkConfiguration := compute.VirtualMachineScaleSetNetworkConfiguration{
		VirtualMachineScaleSetNetworkConfigurationProperties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
			IPConfigurations: &[]compute.VirtualMachineScaleSetIPConfiguration{
				{
					VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
						LoadBalancerBackendAddressPools: &[]compute.SubResource{{ID: ptr.To(testLBBackendpoolID)}},
						Primary:                         ptr.To(true),
					},
				},
			},
		},
	}
	vmssVM := VirtualMachineScaleSet{
		VirtualMachineScaleSet: compute.VirtualMachineScaleSet{
			Location: ptr.To("eastus"),
			VirtualMachineScaleSetProperties: &compute.VirtualMachineScaleSetProperties{
				VirtualMachineProfile: &compute.VirtualMachineScaleSetVMProfile{
					NetworkProfile: &compute.VirtualMachineScaleSetNetworkProfile{
						NetworkInterfaceConfigurations: &[]compute.VirtualMachineScaleSetNetworkConfiguration{
							virtualMachineScaleSetNetworkConfiguration,
						},
					},
				},
				OrchestrationMode: compute.Flexible,
			},
			Tags: map[string]*string{
				consts.VMSetCIDRIPV4TagKey: ptr.To("24"),
				consts.VMSetCIDRIPV6TagKey: ptr.To("64"),
			},
		},
		Etag: ptr.To("\"120\""),
	}
	return vmssVM
}

func TestMarshal(t *testing.T) {
	fakeVmss := getFakeVmssVM()
	fakeVmssWithoutEtag := getFakeVmssVM()
	fakeVmssWithoutEtag.Etag = nil
	fakeVmssWithoutCompueVMSS := getFakeVmssVM()
	fakeVmssWithoutCompueVMSS.VirtualMachineScaleSet = compute.VirtualMachineScaleSet{}
	testcases := []struct {
		name       string
		vmss       VirtualMachineScaleSet
		expectJSON string
	}{

		{
			name:       "should return empty json when vmss is empty",
			vmss:       VirtualMachineScaleSet{},
			expectJSON: "{}",
		},
		{
			name:       "should return only VirtualMachineScaleSet when etag is empty",
			vmss:       fakeVmssWithoutEtag,
			expectJSON: `{"location":"eastus","properties":{"orchestrationMode":"Flexible","virtualMachineProfile":{"networkProfile":{"networkInterfaceConfigurations":[{"properties":{"ipConfigurations":[{"properties":{"primary":true,"loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]}}},"tags":{"kubernetesNodeCIDRMaskIPV4":"24","kubernetesNodeCIDRMaskIPV6":"64"}}`,
		},
		{
			name:       "should return only etag json when vmss is empty",
			vmss:       fakeVmssWithoutCompueVMSS,
			expectJSON: `{"etag":"\"120\""}`,
		},
		{
			name:       "should return full json when both VirtualMachineScaleSet and etag are set",
			vmss:       fakeVmss,
			expectJSON: `{"location":"eastus","properties":{"orchestrationMode":"Flexible","virtualMachineProfile":{"networkProfile":{"networkInterfaceConfigurations":[{"properties":{"ipConfigurations":[{"properties":{"primary":true,"loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]}}},"tags":{"kubernetesNodeCIDRMaskIPV4":"24","kubernetesNodeCIDRMaskIPV6":"64"},"etag":"\"120\""}`,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			actualJSON, err := json.Marshal(tt.vmss)
			assert.Nil(t, err)
			assert.Equal(t, string(actualJSON), tt.expectJSON)
		})
	}
}

func TestUnMarshal(t *testing.T) {
	fakeVmss := getFakeVmssVM()
	fakeVmssWithoutEtag := getFakeVmssVM()
	fakeVmssWithoutEtag.Etag = nil
	fakeVmssWithoutCompueVMSS := getFakeVmssVM()
	fakeVmssWithoutCompueVMSS.VirtualMachineScaleSet = compute.VirtualMachineScaleSet{}
	testcases := []struct {
		name         string
		expectedVmss VirtualMachineScaleSet
		inputJSON    string
	}{
		{
			name:         "should return empty json when vmss is empty",
			expectedVmss: VirtualMachineScaleSet{},
			inputJSON:    "{}",
		},

		{
			name:         "should return only compute.VirtualMachineScaleSetVM when etag is empty",
			expectedVmss: fakeVmssWithoutEtag,
			inputJSON:    `{"location":"eastus","properties":{"orchestrationMode":"Flexible","virtualMachineProfile":{"networkProfile":{"networkInterfaceConfigurations":[{"properties":{"ipConfigurations":[{"properties":{"primary":true,"loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]}}},"tags":{"kubernetesNodeCIDRMaskIPV4":"24","kubernetesNodeCIDRMaskIPV6":"64"}}`,
		},

		{
			name:         "should return only etag json when vmss is empty",
			expectedVmss: fakeVmssWithoutCompueVMSS,
			inputJSON:    `{"etag":"\"120\""}`,
		},

		{
			name:         "should return full json when both VirtualMachineScaleSetVM and etag are set",
			expectedVmss: fakeVmss,
			inputJSON:    `{"location":"eastus","properties":{"orchestrationMode":"Flexible","virtualMachineProfile":{"networkProfile":{"networkInterfaceConfigurations":[{"properties":{"ipConfigurations":[{"properties":{"primary":true,"loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]}}},"tags":{"kubernetesNodeCIDRMaskIPV4":"24","kubernetesNodeCIDRMaskIPV6":"64"},"etag":"\"120\""}`,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			var actualVmss VirtualMachineScaleSet
			err := json.Unmarshal([]byte(tt.inputJSON), &actualVmss)
			assert.Nil(t, err)
			assert.Equal(t, actualVmss, tt.expectedVmss)
		})
	}
}
