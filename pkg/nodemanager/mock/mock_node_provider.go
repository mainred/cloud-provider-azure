/*
Copyright 2019 The Kubernetes Authors.

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

package mock

import (
	context "context"

	cloudprovider "k8s.io/cloud-provider"

	mock "github.com/stretchr/testify/mock"

	types "k8s.io/apimachinery/pkg/types"

	v1 "k8s.io/api/core/v1"
)

// NodeProvider is an autogenerated mock type for the NodeProvider type
type NodeProvider struct {
	mock.Mock
}

// GetZone provides a mock function with given fields: ctx
func (_m *NodeProvider) GetZone(ctx context.Context) (cloudprovider.Zone, error) {
	ret := _m.Called(ctx)

	var r0 cloudprovider.Zone
	if rf, ok := ret.Get(0).(func(context.Context) cloudprovider.Zone); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(cloudprovider.Zone)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InstanceID provides a mock function with given fields: ctx, name
func (_m *NodeProvider) InstanceID(ctx context.Context, name types.NodeName) (string, error) {
	ret := _m.Called(ctx, name)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, types.NodeName) string); ok {
		r0 = rf(ctx, name)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, types.NodeName) error); ok {
		r1 = rf(ctx, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InstanceType provides a mock function with given fields: ctx, name
func (_m *NodeProvider) InstanceType(ctx context.Context, name types.NodeName) (string, error) {
	ret := _m.Called(ctx, name)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, types.NodeName) string); ok {
		r0 = rf(ctx, name)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, types.NodeName) error); ok {
		r1 = rf(ctx, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NodeAddresses provides a mock function with given fields: ctx, name
func (_m *NodeProvider) NodeAddresses(ctx context.Context, name types.NodeName) ([]v1.NodeAddress, error) {
	ret := _m.Called(ctx, name)

	var r0 []v1.NodeAddress
	if rf, ok := ret.Get(0).(func(context.Context, types.NodeName) []v1.NodeAddress); ok {
		r0 = rf(ctx, name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]v1.NodeAddress)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, types.NodeName) error); ok {
		r1 = rf(ctx, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
