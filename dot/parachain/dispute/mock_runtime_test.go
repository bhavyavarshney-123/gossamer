// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/parachain/runtime (interfaces: RuntimeInstance)

// Package parachain is a generated GoMock package.
package dispute

import (
	reflect "reflect"

	parachaintypes "github.com/ChainSafe/gossamer/dot/parachain/types"
	common "github.com/ChainSafe/gossamer/lib/common"
	gomock "github.com/golang/mock/gomock"
)

// MockRuntimeInstance is a mock of RuntimeInstance interface.
type MockRuntimeInstance struct {
	ctrl     *gomock.Controller
	recorder *MockRuntimeInstanceMockRecorder
}

// MockRuntimeInstanceMockRecorder is the mock recorder for MockRuntimeInstance.
type MockRuntimeInstanceMockRecorder struct {
	mock *MockRuntimeInstance
}

// NewMockRuntimeInstance creates a new mock instance.
func NewMockRuntimeInstance(ctrl *gomock.Controller) *MockRuntimeInstance {
	mock := &MockRuntimeInstance{ctrl: ctrl}
	mock.recorder = &MockRuntimeInstanceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRuntimeInstance) EXPECT() *MockRuntimeInstanceMockRecorder {
	return m.recorder
}

// ParachainHostCheckValidationOutputs mocks base method.
func (m *MockRuntimeInstance) ParachainHostCheckValidationOutputs(arg0 uint32, arg1 parachaintypes.CandidateCommitments) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParachainHostCheckValidationOutputs", arg0, arg1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParachainHostCheckValidationOutputs indicates an expected call of ParachainHostCheckValidationOutputs.
func (mr *MockRuntimeInstanceMockRecorder) ParachainHostCheckValidationOutputs(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParachainHostCheckValidationOutputs", reflect.TypeOf((*MockRuntimeInstance)(nil).ParachainHostCheckValidationOutputs), arg0, arg1)
}

// ParachainHostPersistedValidationData mocks base method.
func (m *MockRuntimeInstance) ParachainHostPersistedValidationData(arg0 uint32, arg1 parachaintypes.OccupiedCoreAssumption) (*parachaintypes.PersistedValidationData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParachainHostPersistedValidationData", arg0, arg1)
	ret0, _ := ret[0].(*parachaintypes.PersistedValidationData)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParachainHostPersistedValidationData indicates an expected call of ParachainHostPersistedValidationData.
func (mr *MockRuntimeInstanceMockRecorder) ParachainHostPersistedValidationData(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParachainHostPersistedValidationData", reflect.TypeOf((*MockRuntimeInstance)(nil).ParachainHostPersistedValidationData), arg0, arg1)
}

// ParachainHostSessionIndexForChild mocks base method.
func (m *MockRuntimeInstance) ParachainHostSessionIndexForChild(arg0 common.Hash) (parachaintypes.SessionIndex, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParachainHostSessionIndexForChild", arg0)
	ret0, _ := ret[0].(parachaintypes.SessionIndex)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParachainHostSessionIndexForChild indicates an expected call of ParachainHostSessionIndexForChild.
func (mr *MockRuntimeInstanceMockRecorder) ParachainHostSessionIndexForChild(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParachainHostSessionIndexForChild", reflect.TypeOf((*MockRuntimeInstance)(nil).ParachainHostSessionIndexForChild), arg0)
}

// ParachainHostSessionInfo mocks base method.
func (m *MockRuntimeInstance) ParachainHostSessionInfo(arg0 common.Hash, arg1 parachaintypes.SessionIndex) (*parachaintypes.SessionInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParachainHostSessionInfo", arg0, arg1)
	ret0, _ := ret[0].(*parachaintypes.SessionInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParachainHostSessionInfo indicates an expected call of ParachainHostSessionInfo.
func (mr *MockRuntimeInstanceMockRecorder) ParachainHostSessionInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParachainHostSessionInfo", reflect.TypeOf((*MockRuntimeInstance)(nil).ParachainHostSessionInfo), arg0, arg1)
}

// ParachainHostValidationCode mocks base method.
func (m *MockRuntimeInstance) ParachainHostValidationCode(arg0 uint32, arg1 parachaintypes.OccupiedCoreAssumption) (*parachaintypes.ValidationCode, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParachainHostValidationCode", arg0, arg1)
	ret0, _ := ret[0].(*parachaintypes.ValidationCode)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParachainHostValidationCode indicates an expected call of ParachainHostValidationCode.
func (mr *MockRuntimeInstanceMockRecorder) ParachainHostValidationCode(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParachainHostValidationCode", reflect.TypeOf((*MockRuntimeInstance)(nil).ParachainHostValidationCode), arg0, arg1)
}

// ParachainHostValidationCodeByHash mocks base method.
func (m *MockRuntimeInstance) ParachainHostValidationCodeByHash(arg0 common.Hash, arg1 parachaintypes.ValidationCodeHash) (*parachaintypes.ValidationCode, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ParachainHostValidationCodeByHash", arg0, arg1)
	ret0, _ := ret[0].(*parachaintypes.ValidationCode)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ParachainHostValidationCodeByHash indicates an expected call of ParachainHostValidationCodeByHash.
func (mr *MockRuntimeInstanceMockRecorder) ParachainHostValidationCodeByHash(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ParachainHostValidationCodeByHash", reflect.TypeOf((*MockRuntimeInstance)(nil).ParachainHostValidationCodeByHash), arg0, arg1)
}
