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

package vmssvmclient

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
	testResourceID     = "/subscriptions/subscriptionID/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/0"
	testResourcePrefix = "/subscriptions/subscriptionID/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines"
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

	vmssvmClient := New(config)
	assert.Equal(t, "sub", vmssvmClient.subscriptionID)
	assert.NotEmpty(t, vmssvmClient.rateLimiterReader)
	assert.NotEmpty(t, vmssvmClient.rateLimiterWriter)
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

	vmssvmClient := New(config)
	assert.Equal(t, "AZURESTACKCLOUD", vmssvmClient.cloudName)
	assert.Equal(t, "sub", vmssvmClient.subscriptionID)
}

func TestGet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourceID, "InstanceView").Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	expected := VirtualMachineScaleSetVM{VirtualMachineScaleSetVM: compute.VirtualMachineScaleSetVM{Response: autorest.Response{Response: response}}}
	vmssvmClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssvmClient.Get(context.TODO(), "rg", "vmss1", "0", "InstanceView")
	assert.Equal(t, expected, result)
	assert.Nil(t, rerr)
}

func TestGetNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssvmGetErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "read", "VMSSVMGet"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmClient := getTestVMSSVMClientWithNeverRateLimiter(armClient)
	expected := VirtualMachineScaleSetVM{}
	result, rerr := vmssvmClient.Get(context.TODO(), "rg", "vmss1", "0", "InstanceView")
	assert.Equal(t, expected, result)
	assert.Equal(t, vmssvmGetErr, rerr)
}

func TestGetRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssvmGetErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSVMGet", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmClient := getTestVMSSVMClientWithRetryAfterReader(armClient)
	expected := VirtualMachineScaleSetVM{}
	result, rerr := vmssvmClient.Get(context.TODO(), "rg", "vmss1", "0", "InstanceView")
	assert.Equal(t, expected, result)
	assert.Equal(t, vmssvmGetErr, rerr)
}

func TestGetNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourceID, "InstanceView").Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSVMClient(armClient)
	expectedVM := VirtualMachineScaleSetVM{VirtualMachineScaleSetVM: compute.VirtualMachineScaleSetVM{Response: autorest.Response{}}}
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1", "0", "InstanceView")
	assert.Equal(t, expectedVM, result)
	assert.NotNil(t, rerr)
	assert.Equal(t, http.StatusNotFound, rerr.HTTPStatusCode)
}

func TestGetInternalError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	resourceID := "/subscriptions/subscriptionID/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/1"
	response := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), resourceID, "InstanceView").Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSVMClient(armClient)
	expectedVM := VirtualMachineScaleSetVM{VirtualMachineScaleSetVM: compute.VirtualMachineScaleSetVM{Response: autorest.Response{}}}
	result, rerr := vmssClient.Get(context.TODO(), "rg", "vmss1", "1", "InstanceView")
	assert.Equal(t, expectedVM, result)
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
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourceID, "InstanceView").Return(response, throttleErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssvmClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssvmClient.Get(context.TODO(), "rg", "vmss1", "0", "InstanceView")
	assert.Empty(t, result)
	assert.Equal(t, throttleErr, rerr)
}

func TestList(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssList := []VirtualMachineScaleSetVM{getTestVMSSVM("vmss1", "1"), getTestVMSSVM("vmss1", "2"), getTestVMSSVM("vmss1", "3")}
	responseBody, err := json.Marshal(VirtualMachineScaleSetVMListResult{Value: &vmssList})
	assert.NoError(t, err)
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourcePrefix, "InstanceView").Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
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
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourcePrefix, "InstanceView").Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssvmClient := getTestVMSSVMClient(armClient)
	expected := []VirtualMachineScaleSetVM{}
	result, rerr := vmssvmClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
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
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourcePrefix, "InstanceView").Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssvmClient := getTestVMSSVMClient(armClient)
	expected := []VirtualMachineScaleSetVM{}
	result, rerr := vmssvmClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
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
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourcePrefix, "InstanceView").Return(response, throttleErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	vmssvmClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssvmClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
	assert.Empty(t, result)
	assert.NotNil(t, rerr)
	assert.Equal(t, throttleErr, rerr)
}

func TestListWithListResponderError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmList := []VirtualMachineScaleSetVM{getTestVMSSVM("vmss1", "1"), getTestVMSSVM("vmss1", "2"), getTestVMSSVM("vmss1", "3")}
	responseBody, err := json.Marshal(VirtualMachineScaleSetVMListResult{Value: &vmssvmList})
	assert.NoError(t, err)
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourcePrefix, "InstanceView").Return(
		&http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	vmssvmClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssvmClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
	assert.NotNil(t, rerr)
	assert.Equal(t, 0, len(result))
}

func TestListWithNextPage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmList := []VirtualMachineScaleSetVM{getTestVMSSVM("vmss1", "1"), getTestVMSSVM("vmss1", "2"), getTestVMSSVM("vmss1", "3")}
	partialResponse, err := json.Marshal(VirtualMachineScaleSetVMListResult{Value: &vmssvmList, NextLink: ptr.To("nextLink")})
	assert.NoError(t, err)
	pagedResponse, err := json.Marshal(VirtualMachineScaleSetVMListResult{Value: &vmssvmList})
	assert.NoError(t, err)
	armClient.EXPECT().PrepareGetRequest(gomock.Any(), gomock.Any()).Return(&http.Request{}, nil)
	armClient.EXPECT().Send(gomock.Any(), gomock.Any()).Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(pagedResponse)),
		}, nil)
	armClient.EXPECT().GetResourceWithExpandQuery(gomock.Any(), testResourcePrefix, "InstanceView").Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(partialResponse)),
		}, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(2)
	vmssvmClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssvmClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
	assert.Nil(t, rerr)
	assert.Equal(t, 6, len(result))
}

func TestListNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssvmListErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "read", "VMSSVMList"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmClient := getTestVMSSVMClientWithNeverRateLimiter(armClient)
	result, rerr := vmssvmClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
	assert.Equal(t, 0, len(result))
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssvmListErr, rerr)
}

func TestListRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssvmListErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSVMList", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmClient := getTestVMSSVMClientWithRetryAfterReader(armClient)
	result, rerr := vmssvmClient.List(context.TODO(), "rg", "vmss1", "InstanceView")
	assert.Equal(t, 0, len(result))
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssvmListErr, rerr)
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

	lastResult := VirtualMachineScaleSetVMListResult{
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

		vmssClient := getTestVMSSVMClient(armClient)
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

	lastResult := VirtualMachineScaleSetVMListResult{
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
		expected := compute.VirtualMachineScaleSetVMListResult{}
		expected.Response = autorest.Response{Response: response}
		vmssClient := getTestVMSSVMClient(armClient)
		result, err := vmssClient.listNextResults(context.TODO(), lastResult)
		assert.Error(t, err)
		if test.sendErr != nil {
			assert.NotEqual(t, expected, result)
		} else {
			assert.Equal(t, expected, result)
		}
	}
}

func TestUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM := getTestVMSSVM("vmss1", "0")
	armClient := mockarmclient.NewMockInterface(ctrl)
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	armClient.EXPECT().PutResource(gomock.Any(), ptr.Deref(vmssVM.ID, ""), vmssVM).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	expected := &VirtualMachineScaleSetVM{}
	expected.Response = autorest.Response{Response: response}

	vmssClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssClient.Update(context.TODO(), "rg", "vmss1", "0", vmssVM, "test", "")
	assert.Nil(t, rerr)
	assert.Equal(t, expected, result)
}

func TestUpdateAsync(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM := getTestVMSSVM("vmss1", "0")
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResourceAsync(gomock.Any(), ptr.Deref(vmssVM.ID, ""), vmssVM).Return(nil, nil).Times(1)

	vmssClient := getTestVMSSVMClient(armClient)
	future, rerr := vmssClient.UpdateAsync(context.TODO(), "rg", "vmss1", "0", vmssVM, "test", "")
	assert.Nil(t, rerr)
	assert.Nil(t, future)
}

func TestWaitForUpdateResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	preemptErr := fmt.Errorf("operation execution has been preempted by a more recent operation")
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}

	tests := []struct {
		name           string
		response       *http.Response
		responseErr    error
		expectedResult *retry.Error
	}{
		{
			name:           "Success",
			response:       response,
			responseErr:    nil,
			expectedResult: nil,
		},
		{
			name:           "Success with nil response",
			response:       nil,
			responseErr:    nil,
			expectedResult: nil,
		},
		{
			name:           "Failed",
			response:       response,
			responseErr:    preemptErr,
			expectedResult: retry.GetError(response, preemptErr),
		},
		{
			name:           "Failed with nil response",
			response:       nil,
			responseErr:    preemptErr,
			expectedResult: retry.GetError(nil, preemptErr),
		},
	}

	for _, test := range tests {
		armClient := mockarmclient.NewMockInterface(ctrl)
		armClient.EXPECT().WaitForAsyncOperationResult(gomock.Any(), gomock.Any(), "VMSSWaitForUpdateResult").Return(test.response, test.responseErr).Times(1)
		armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

		vmssClient := getTestVMSSVMClient(armClient)
		response, err := vmssClient.WaitForUpdateResult(context.TODO(), &azure.Future{}, "rg", "test")
		assert.Equal(t, err, test.expectedResult)
		var output *VirtualMachineScaleSetVM
		if err == nil {
			output = &VirtualMachineScaleSetVM{}
			output.Response = autorest.Response{Response: test.response}
		}
		assert.Equal(t, response, output)
	}
}

func TestUpdateWithUpdateResponderError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM := getTestVMSSVM("vmss1", "0")
	armClient := mockarmclient.NewMockInterface(ctrl)
	response := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	armClient.EXPECT().PutResource(gomock.Any(), ptr.Deref(vmssVM.ID, ""), vmssVM).Return(response, nil).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)
	expected := &VirtualMachineScaleSetVM{}
	expected.Response = autorest.Response{Response: response}

	vmssvmClient := getTestVMSSVMClient(armClient)
	result, rerr := vmssvmClient.Update(context.TODO(), "rg", "vmss1", "0", vmssVM, "test", "")
	assert.NotNil(t, rerr)
	assert.Equal(t, expected, result)
}

func TestUpdateNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssvmUpdateErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "write", "VMSSVMUpdate"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmClient := getTestVMSSVMClientWithNeverRateLimiter(armClient)
	vmssVM := getTestVMSSVM("vmss1", "0")
	var expected *VirtualMachineScaleSetVM
	result, rerr := vmssvmClient.Update(context.TODO(), "rg", "vmss1", "0", vmssVM, "test", "")
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssvmUpdateErr, rerr)
	assert.Equal(t, expected, result)
}

func TestUpdateRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssvmUpdateErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSVMUpdate", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	vmssVM := getTestVMSSVM("vmss1", "0")
	armClient := mockarmclient.NewMockInterface(ctrl)
	vmClient := getTestVMSSVMClientWithRetryAfterReader(armClient)
	var expected *VirtualMachineScaleSetVM
	result, rerr := vmClient.Update(context.TODO(), "rg", "vmss1", "0", vmssVM, "test", "")
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssvmUpdateErr, rerr)
	assert.Equal(t, expected, result)
}

func TestUpdateThrottle(t *testing.T) {
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

	vmssVM := getTestVMSSVM("vmss1", "0")
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResource(gomock.Any(), ptr.Deref(vmssVM.ID, ""), vmssVM).Return(response, throttleErr).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssvmClient := getTestVMSSVMClient(armClient)
	var expected *VirtualMachineScaleSetVM
	result, rerr := vmssvmClient.Update(context.TODO(), "rg", "vmss1", "0", vmssVM, "test", "")
	assert.NotNil(t, rerr)
	assert.Equal(t, throttleErr, rerr)
	assert.Equal(t, expected, result)
}

func TestUpdateVMs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM1 := getTestVMSSVM("vmss1", "1")
	vmssVM2 := getTestVMSSVM("vmss1", "2")
	instances := map[string]VirtualMachineScaleSetVM{
		"1": vmssVM1,
		"2": vmssVM2,
	}
	testvmssVMs := map[string]interface{}{
		ptr.Deref(vmssVM1.ID, ""): vmssVM1,
		ptr.Deref(vmssVM2.ID, ""): vmssVM2,
	}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	responses := map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM1.ID, ""): {
			Response: response,
		},
		ptr.Deref(vmssVM2.ID, ""): {
			Response: response,
		},
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs, 0).Return(responses).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(2)

	vmssvmClient := getTestVMSSVMClient(armClient)
	rerr := vmssvmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.Nil(t, rerr)
}

func TestUpdateVMsWithUpdateVMsResponderError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM := getTestVMSSVM("vmss1", "1")
	instances := map[string]VirtualMachineScaleSetVM{
		"1": vmssVM,
	}
	testvmssVMs := map[string]interface{}{
		ptr.Deref(vmssVM.ID, ""): vmssVM,
	}
	response := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	responses := map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM.ID, ""): {
			Response: response,
		},
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs, 0).Return(responses).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssvmClient := getTestVMSSVMClient(armClient)
	rerr := vmssvmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.NotNil(t, rerr)
}

func TestUpdateVMsPreemptedRetry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM1 := getTestVMSSVM("vmss1", "1")
	vmssVM2 := getTestVMSSVM("vmss1", "2")
	instances := map[string]VirtualMachineScaleSetVM{
		"1": vmssVM1,
		"2": vmssVM2,
	}
	testvmssVMs1 := map[string]interface{}{
		ptr.Deref(vmssVM1.ID, ""): vmssVM1,
		ptr.Deref(vmssVM2.ID, ""): vmssVM2,
	}
	testvmssVMs2 := map[string]interface{}{
		ptr.Deref(vmssVM2.ID, ""): vmssVM2,
	}
	resp1 := &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	resp2 := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}
	preemptErr := retry.NewError(false, errors.New(consts.OperationPreemptedErrorMessage))
	resps1 := map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM1.ID, ""): {Response: resp1},
		ptr.Deref(vmssVM2.ID, ""): {Response: resp2, Error: preemptErr},
	}
	resps2 := map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM2.ID, ""): {Response: resp2, Error: preemptErr},
	}
	armClient := mockarmclient.NewMockInterface(ctrl)
	firstPut := armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs1, 0).Return(resps1)
	armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs2, 0).Return(resps2).After(firstPut)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(3)

	vmssvmClient := getTestVMSSVMClient(armClient)
	rerr := vmssvmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.NotNil(t, rerr)
	assert.Contains(t, rerr.RawError.Error(), consts.OperationPreemptedErrorMessage)

	resps1 = map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM2.ID, ""): {Response: resp2, Error: preemptErr},
	}
	resps2 = map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM2.ID, ""): {Response: resp2},
	}
	firstPut = armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs1, 0).Return(resps1)
	armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs2, 0).Return(resps2).After(firstPut)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(2)

	vmssvmClient = getTestVMSSVMClient(armClient)
	rerr = vmssvmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.Nil(t, rerr)
}

func TestUpdateVMsNeverRateLimiter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	instances := map[string]VirtualMachineScaleSetVM{}
	vmssvmUpdateVMsErr := &retry.Error{
		RawError:  fmt.Errorf("azure cloud provider rate limited(%s) for operation %q", "write", "VMSSVMUpdateVMs"),
		Retriable: true,
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmssvmClient := getTestVMSSVMClientWithNeverRateLimiter(armClient)
	rerr := vmssvmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssvmUpdateVMsErr, rerr)
}

func TestUpdateVMsRetryAfterReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	instances := map[string]VirtualMachineScaleSetVM{}
	vmssvmUpdateVMsErr := &retry.Error{
		RawError:   fmt.Errorf("azure cloud provider throttled for operation %s with reason %q", "VMSSVMUpdateVMs", "client throttled"),
		Retriable:  true,
		RetryAfter: getFutureTime(),
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	vmClient := getTestVMSSVMClientWithRetryAfterReader(armClient)
	rerr := vmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.NotNil(t, rerr)
	assert.Equal(t, vmssvmUpdateVMsErr, rerr)
}

func TestUpdateVMsThrottle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM := getTestVMSSVM("vmss1", "1")
	instances := map[string]VirtualMachineScaleSetVM{
		"1": vmssVM,
	}
	testvmssVMs := map[string]interface{}{
		ptr.Deref(vmssVM.ID, ""): vmssVM,
	}
	throttleErr := retry.Error{
		HTTPStatusCode: http.StatusTooManyRequests,
		RawError:       fmt.Errorf("error"),
		Retriable:      true,
		RetryAfter:     time.Unix(100, 0),
	}
	responses := map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM.ID, ""): {
			Response: &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
			},
			Error: &throttleErr,
		},
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs, 0).Return(responses).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(1)

	vmssvmClient := getTestVMSSVMClient(armClient)
	rerr := vmssvmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.NotNil(t, rerr)
	assert.EqualError(t, throttleErr.Error(), rerr.RawError.Error())
}

func TestUpdateVMsIgnoreError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	vmssVM := getTestVMSSVM("vmss1", "1")
	vmssVM2 := getTestVMSSVM("vmss1", "2")
	vmssVM3 := getTestVMSSVM("vmss1", "3")
	vmssVM4 := getTestVMSSVM("vmss1", "4")
	instances := map[string]VirtualMachineScaleSetVM{
		"1": vmssVM,
		"2": vmssVM2,
		"3": vmssVM3,
		"4": vmssVM4,
	}
	testvmssVMs := map[string]interface{}{
		ptr.Deref(vmssVM.ID, ""):  vmssVM,
		ptr.Deref(vmssVM2.ID, ""): vmssVM2,
		ptr.Deref(vmssVM3.ID, ""): vmssVM3,
		ptr.Deref(vmssVM4.ID, ""): vmssVM4,
	}
	notActiveError := retry.Error{
		RawError:  fmt.Errorf(consts.VmssVMNotActiveErrorMessage),
		Retriable: false,
	}
	parentResourceNotFoundError := retry.Error{
		RawError:  fmt.Errorf(consts.ParentResourceNotFoundMessageCode),
		Retriable: false,
	}
	concurrentRequestConflictError := retry.Error{
		RawError:  fmt.Errorf(consts.ConcurrentRequestConflictMessage),
		Retriable: false,
	}
	beingDeletedError := retry.Error{
		RawError:  fmt.Errorf("operation 'Put on Virtual Machine Scale Set VM Instance' is not allowed on Virtual Machine Scale Set 'aks-stg1pool1-17586529-vmss' since it is marked for deletion. For more information on your operations, please refer to https://aka.ms/activitylog"),
		Retriable: false,
	}
	responses := map[string]*armclient.PutResourcesResponse{
		ptr.Deref(vmssVM.ID, ""): {
			Error: &notActiveError,
		},
		ptr.Deref(vmssVM2.ID, ""): {
			Error: &parentResourceNotFoundError,
		},
		ptr.Deref(vmssVM3.ID, ""): {
			Error: &concurrentRequestConflictError,
		},
		ptr.Deref(vmssVM4.ID, ""): {
			Error: &beingDeletedError,
		},
	}

	armClient := mockarmclient.NewMockInterface(ctrl)
	armClient.EXPECT().PutResourcesInBatches(gomock.Any(), testvmssVMs, 0).Return(responses).Times(1)
	armClient.EXPECT().CloseResponse(gomock.Any(), gomock.Any()).Times(len(instances))

	vmssvmClient := getTestVMSSVMClient(armClient)
	rerr := vmssvmClient.UpdateVMs(context.TODO(), "rg", "vmss1", instances, "test", 0)
	assert.NotNil(t, rerr)
	assert.Equal(t, rerr.Error().Error(), "Retriable: false, RetryAfter: 4s, HTTPStatusCode: 0, RawError: Retriable: true, RetryAfter: 4s, HTTPStatusCode: 0, RawError: The request failed due to conflict with a concurrent request.")
}

func getTestVMSSVM(vmssName, instanceID string) VirtualMachineScaleSetVM {
	resourceID := fmt.Sprintf("/subscriptions/subscriptionID/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/%s/virtualMachines/%s", vmssName, instanceID)
	return VirtualMachineScaleSetVM{
		VirtualMachineScaleSetVM: compute.VirtualMachineScaleSetVM{
			ID:         ptr.To(resourceID),
			InstanceID: ptr.To(instanceID),
			Location:   ptr.To("eastus"),
		},
	}

}

func getTestVMSSVMClient(armClient armclient.Interface) *Client {
	rateLimiterReader, rateLimiterWriter := azclients.NewRateLimiter(&azclients.RateLimitConfig{})
	return &Client{
		armClient:         armClient,
		subscriptionID:    "subscriptionID",
		rateLimiterReader: rateLimiterReader,
		rateLimiterWriter: rateLimiterWriter,
	}
}

func getTestVMSSVMClientWithNeverRateLimiter(armClient armclient.Interface) *Client {
	rateLimiterReader := flowcontrol.NewFakeNeverRateLimiter()
	rateLimiterWriter := flowcontrol.NewFakeNeverRateLimiter()
	return &Client{
		armClient:         armClient,
		subscriptionID:    "subscriptionID",
		rateLimiterReader: rateLimiterReader,
		rateLimiterWriter: rateLimiterWriter,
	}
}

func getTestVMSSVMClientWithRetryAfterReader(armClient armclient.Interface) *Client {
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

func getFakeVmssVM() VirtualMachineScaleSetVM {
	index := 0
	scaleSetName := "fakevmss"
	interfaceID := fmt.Sprintf("/subscriptions/fakesub/resourceGroups/fakerg/providers/Microsoft.Compute/virtualMachineScaleSets/%s/virtualMachines/%d/networkInterfaces/fakenic", scaleSetName, index)
	nodeName := fmt.Sprintf("%s000000", scaleSetName)
	testLBBackendpoolID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"

	// set vmss virtual machine.
	networkInterfaces := []compute.NetworkInterfaceReference{
		{
			ID: &interfaceID,
			NetworkInterfaceReferenceProperties: &compute.NetworkInterfaceReferenceProperties{
				Primary: ptr.To(true),
			},
		},
	}
	ipConfigurations := []compute.VirtualMachineScaleSetIPConfiguration{
		{
			Name: ptr.To("ipconfig1"),
			VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
				Primary:                         ptr.To(true),
				LoadBalancerBackendAddressPools: &[]compute.SubResource{{ID: ptr.To(testLBBackendpoolID)}},
				PrivateIPAddressVersion:         compute.IPv4,
			},
		},
	}
	networkConfigurations := []compute.VirtualMachineScaleSetNetworkConfiguration{
		{
			Name: ptr.To("vmss-nic"),
			ID:   ptr.To("fakeNetworkConfiguration"),
			VirtualMachineScaleSetNetworkConfigurationProperties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
				IPConfigurations: &ipConfigurations,
				Primary:          ptr.To(true),
			},
		},
	}

	vmssVM := VirtualMachineScaleSetVM{
		VirtualMachineScaleSetVM: compute.VirtualMachineScaleSetVM{
			VirtualMachineScaleSetVMProperties: &compute.VirtualMachineScaleSetVMProperties{
				OsProfile: &compute.OSProfile{
					ComputerName: &nodeName,
				},
				NetworkProfile: &compute.NetworkProfile{
					NetworkInterfaces: &networkInterfaces,
				},
				HardwareProfile: &compute.HardwareProfile{
					VMSize: compute.StandardD2sV3,
				},
				NetworkProfileConfiguration: &compute.VirtualMachineScaleSetVMNetworkProfileConfiguration{
					NetworkInterfaceConfigurations: &networkConfigurations,
				},
			},
			Location: ptr.To("eastus"),
		},
		Etag: ptr.To("\"120\""),
	}
	return vmssVM
}

func TestMarshal(t *testing.T) {
	fakeVmssVM := getFakeVmssVM()
	fakeVmssVMWithoutEtag := getFakeVmssVM()
	fakeVmssVMWithoutEtag.Etag = nil
	fakeVmssVMWithoutCompueVMSSVM := getFakeVmssVM()
	fakeVmssVMWithoutCompueVMSSVM.VirtualMachineScaleSetVM = compute.VirtualMachineScaleSetVM{}
	testcases := []struct {
		name       string
		vmss       VirtualMachineScaleSetVM
		expectJson string
	}{

		{
			name:       "should return empty json when vmss is empty",
			vmss:       VirtualMachineScaleSetVM{},
			expectJson: "{}",
		},
		{
			name:       "should return only compute.VirtualMachineScaleSetVM when etag is empty",
			vmss:       fakeVmssVMWithoutEtag,
			expectJson: `{"location":"eastus","properties":{"hardwareProfile":{"vmSize":"Standard_D2s_v3"},"networkProfile":{"networkInterfaces":[{"id":"/subscriptions/fakesub/resourceGroups/fakerg/providers/Microsoft.Compute/virtualMachineScaleSets/fakevmss/virtualMachines/0/networkInterfaces/fakenic","properties":{"primary":true}}]},"networkProfileConfiguration":{"networkInterfaceConfigurations":[{"id":"fakeNetworkConfiguration","name":"vmss-nic","properties":{"primary":true,"ipConfigurations":[{"name":"ipconfig1","properties":{"primary":true,"privateIPAddressVersion":"IPv4","loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]},"osProfile":{"computerName":"fakevmss000000"}}}`,
		},
		{
			name:       "should return only etag json when vmss is empty",
			vmss:       fakeVmssVMWithoutCompueVMSSVM,
			expectJson: `{"etag":"\"120\""}`,
		},

		{
			name:       "should return full json when both VirtualMachineScaleSetVM and etag are set",
			vmss:       fakeVmssVM,
			expectJson: `{"location":"eastus","properties":{"hardwareProfile":{"vmSize":"Standard_D2s_v3"},"networkProfile":{"networkInterfaces":[{"id":"/subscriptions/fakesub/resourceGroups/fakerg/providers/Microsoft.Compute/virtualMachineScaleSets/fakevmss/virtualMachines/0/networkInterfaces/fakenic","properties":{"primary":true}}]},"networkProfileConfiguration":{"networkInterfaceConfigurations":[{"id":"fakeNetworkConfiguration","name":"vmss-nic","properties":{"primary":true,"ipConfigurations":[{"name":"ipconfig1","properties":{"primary":true,"privateIPAddressVersion":"IPv4","loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]},"osProfile":{"computerName":"fakevmss000000"}},"etag":"\"120\""}`,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			actualJson, err := json.Marshal(tt.vmss)
			fmt.Println(string(actualJson))
			assert.Nil(t, err)
			assert.Equal(t, string(actualJson), tt.expectJson)
		})
	}
}

func TestUnMarshal(t *testing.T) {
	fakeVmssVM := getFakeVmssVM()
	fakeVmssVMWithoutEtag := getFakeVmssVM()
	fakeVmssVMWithoutEtag.Etag = nil
	fakeVmssVMWithoutCompueVMSSVM := getFakeVmssVM()
	fakeVmssVMWithoutCompueVMSSVM.VirtualMachineScaleSetVM = compute.VirtualMachineScaleSetVM{}
	testcases := []struct {
		name           string
		expectedVmssVM VirtualMachineScaleSetVM
		inputJson      string
	}{
		{
			name:           "should return empty json when vmss is empty",
			expectedVmssVM: VirtualMachineScaleSetVM{},
			inputJson:      "{}",
		},

		{
			name:           "should return only compute.VirtualMachineScaleSetVM when etag is empty",
			expectedVmssVM: fakeVmssVMWithoutEtag,
			inputJson:      `{"location":"eastus","properties":{"hardwareProfile":{"vmSize":"Standard_D2s_v3"},"networkProfile":{"networkInterfaces":[{"id":"/subscriptions/fakesub/resourceGroups/fakerg/providers/Microsoft.Compute/virtualMachineScaleSets/fakevmss/virtualMachines/0/networkInterfaces/fakenic","properties":{"primary":true}}]},"networkProfileConfiguration":{"networkInterfaceConfigurations":[{"id":"fakeNetworkConfiguration","name":"vmss-nic","properties":{"primary":true,"ipConfigurations":[{"name":"ipconfig1","properties":{"primary":true,"privateIPAddressVersion":"IPv4","loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]},"osProfile":{"computerName":"fakevmss000000"}}}`,
		},

		{
			name:           "should return only etag json when vmss is empty",
			expectedVmssVM: fakeVmssVMWithoutCompueVMSSVM,
			inputJson:      `{"etag":"\"120\""}`,
		},

		{
			name:           "should return full json when both VirtualMachineScaleSetVM and etag are set",
			expectedVmssVM: fakeVmssVM,
			inputJson:      `{"location":"eastus","properties":{"hardwareProfile":{"vmSize":"Standard_D2s_v3"},"networkProfile":{"networkInterfaces":[{"id":"/subscriptions/fakesub/resourceGroups/fakerg/providers/Microsoft.Compute/virtualMachineScaleSets/fakevmss/virtualMachines/0/networkInterfaces/fakenic","properties":{"primary":true}}]},"networkProfileConfiguration":{"networkInterfaceConfigurations":[{"id":"fakeNetworkConfiguration","name":"vmss-nic","properties":{"primary":true,"ipConfigurations":[{"name":"ipconfig1","properties":{"primary":true,"privateIPAddressVersion":"IPv4","loadBalancerBackendAddressPools":[{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb/backendAddressPools/backendpool-0"}]}}]}}]},"osProfile":{"computerName":"fakevmss000000"}},"etag":"\"120\""}`,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			var actualVmssVM VirtualMachineScaleSetVM
			err := json.Unmarshal([]byte(tt.inputJson), &actualVmssVM)
			assert.Nil(t, err)
			assert.Equal(t, actualVmssVM, tt.expectedVmssVM)
		})
	}
}
