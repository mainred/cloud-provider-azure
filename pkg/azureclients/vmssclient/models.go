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
	"context"
	"encoding/json"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2022-08-01/compute"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/to"
)

// VirtualMachineScaleSet wraps the original VirtualMachineScaleSet struct and adds an Etag field.
type VirtualMachineScaleSet struct {
	compute.VirtualMachineScaleSet `json:",inline"`
	// READ-ONLY; Etag is property returned in Create/Update/Get response of the VMSS, so that customer can supply it in the header
	// to ensure optimistic updates
	Etag *string `json:"etag,omitempty"`
}

// VirtualMachineScaleSetListResult the List Virtual Machine operation response.
type VirtualMachineScaleSetListResult struct {
	autorest.Response `json:"-"`
	// Value - The list of virtual machine scale sets.
	Value *[]VirtualMachineScaleSet `json:"value,omitempty"`
	// NextLink - The uri to fetch the next page of Virtual Machine Scale Sets. Call ListNext() with this to fetch the next page of VMSS.
	NextLink *string `json:"nextLink,omitempty"`
}

// IsEmpty returns true if the ListResult contains no values.
func (vmsslr VirtualMachineScaleSetListResult) IsEmpty() bool {
	return vmsslr.Value == nil || len(*vmsslr.Value) == 0
}

// hasNextLink returns true if the NextLink is not empty.
func (vmsslr VirtualMachineScaleSetListResult) hasNextLink() bool {
	return vmsslr.NextLink != nil && len(*vmsslr.NextLink) != 0
}

// virtualMachineScaleSetListResultPreparer prepares a request to retrieve the next set of results.
// It returns nil if no more results exist.
func (vmsslr VirtualMachineScaleSetListResult) virtualMachineScaleSetListResultPreparer(ctx context.Context) (*http.Request, error) {
	if !vmsslr.hasNextLink() {
		return nil, nil
	}
	return autorest.Prepare((&http.Request{}).WithContext(ctx),
		autorest.AsJSON(),
		autorest.AsGet(),
		autorest.WithBaseURL(to.String(vmsslr.NextLink)))
}

// UnmarshalJSON is the custom unmarshaler for VirtualMachineScaleSetVM struct.
// compute.VirtualMachineScaleSet implemented `UnmarshalJSON` method, and when the response is unmarshaled into VirtualMachineScaleSet,
// compute.VirtualMachineScaleSet.UnmarshalJSON is called, leading to the loss of the Etag field.
func (vmss *VirtualMachineScaleSet) UnmarshalJSON(data []byte) error {
	// Unmarshal Etag first
	etagPlaceholder := struct {
		Etag *string `json:"etag,omitempty"`
	}{}
	if err := json.Unmarshal(data, &etagPlaceholder); err != nil {
		return err
	}
	// Unmarshal Nested VirtualMachineScaleSet
	nestedVirtualMachineScaleSet := struct {
		compute.VirtualMachineScaleSet `json:",inline"`
	}{}
	// the Nested impl UnmarshalJSON, so it should be unmarshaled alone
	if err := json.Unmarshal(data, &nestedVirtualMachineScaleSet); err != nil {
		return err
	}
	(vmss).Etag = etagPlaceholder.Etag
	(vmss).VirtualMachineScaleSet = nestedVirtualMachineScaleSet.VirtualMachineScaleSet
	return nil
}

// MarshalJSON is the custom marshaler for VirtualMachineScaleSet.
func (vmss VirtualMachineScaleSet) MarshalJSON() ([]byte, error) {
	var err error
	var nestedVirtualMachineScaleSetJSON, etagJSON []byte
	if nestedVirtualMachineScaleSetJSON, err = vmss.VirtualMachineScaleSet.MarshalJSON(); err != nil {
		return nil, err
	}

	if vmss.Etag != nil {
		if etagJSON, err = json.Marshal(map[string]interface{}{
			"etag": vmss.Etag,
		}); err != nil {
			return nil, err
		}
	}

	// empty struct can be Unmarshaled to "{}"
	nestedVirtualMachineScaleSetJSONEmpty := true
	if string(nestedVirtualMachineScaleSetJSON) != "{}" {
		nestedVirtualMachineScaleSetJSONEmpty = false
	}
	etagJSONEmpty := true
	if len(etagJSON) != 0 {
		etagJSONEmpty = false
	}

	// when both parts not empty, join the two parts with a comma but remove the open brace of nestedVirtualMachineScaleSetVMJson and the close brace of the etagJson
	// {"location": "eastus"} + {"etag": "\"120\""} will be merged into {"location": "eastus", "etag": "\"120\""}
	if !nestedVirtualMachineScaleSetJSONEmpty && !etagJSONEmpty {
		etagJSON[0] = ','
		return append(nestedVirtualMachineScaleSetJSON[:len(nestedVirtualMachineScaleSetJSON)-1], etagJSON...), nil
	}
	if !nestedVirtualMachineScaleSetJSONEmpty {
		return nestedVirtualMachineScaleSetJSON, nil
	}
	if !etagJSONEmpty {
		return etagJSON, nil
	}
	return []byte("{}"), nil
}
