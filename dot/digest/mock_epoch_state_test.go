// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/digest (interfaces: EpochState)

// Package digest is a generated GoMock package.
package digest

import (
	reflect "reflect"

	types "github.com/ChainSafe/gossamer/dot/types"
	common "github.com/ChainSafe/gossamer/lib/common"
	gomock "github.com/golang/mock/gomock"
)

// MockEpochState is a mock of EpochState interface.
type MockEpochState struct {
	ctrl     *gomock.Controller
	recorder *MockEpochStateMockRecorder
}

// MockEpochStateMockRecorder is the mock recorder for MockEpochState.
type MockEpochStateMockRecorder struct {
	mock *MockEpochState
}

// NewMockEpochState creates a new mock instance.
func NewMockEpochState(ctrl *gomock.Controller) *MockEpochState {
	mock := &MockEpochState{ctrl: ctrl}
	mock.recorder = &MockEpochStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockEpochState) EXPECT() *MockEpochStateMockRecorder {
	return m.recorder
}

// FinalizeBABENextConfigData mocks base method.
func (m *MockEpochState) FinalizeBABENextConfigData(arg0 *types.Header) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FinalizeBABENextConfigData", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// FinalizeBABENextConfigData indicates an expected call of FinalizeBABENextConfigData.
func (mr *MockEpochStateMockRecorder) FinalizeBABENextConfigData(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FinalizeBABENextConfigData", reflect.TypeOf((*MockEpochState)(nil).FinalizeBABENextConfigData), arg0)
}

// FinalizeBABENextEpochData mocks base method.
func (m *MockEpochState) FinalizeBABENextEpochData(arg0 *types.Header) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FinalizeBABENextEpochData", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// FinalizeBABENextEpochData indicates an expected call of FinalizeBABENextEpochData.
func (mr *MockEpochStateMockRecorder) FinalizeBABENextEpochData(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FinalizeBABENextEpochData", reflect.TypeOf((*MockEpochState)(nil).FinalizeBABENextEpochData), arg0)
}

// GetEpochForBlock mocks base method.
func (m *MockEpochState) GetEpochForBlock(arg0 *types.Header) (uint64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEpochForBlock", arg0)
	ret0, _ := ret[0].(uint64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEpochForBlock indicates an expected call of GetEpochForBlock.
func (mr *MockEpochStateMockRecorder) GetEpochForBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEpochForBlock", reflect.TypeOf((*MockEpochState)(nil).GetEpochForBlock), arg0)
}

// SetConfigData mocks base method.
func (m *MockEpochState) SetConfigData(arg0 uint64, arg1 *types.ConfigData) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetConfigData", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetConfigData indicates an expected call of SetConfigData.
func (mr *MockEpochStateMockRecorder) SetConfigData(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetConfigData", reflect.TypeOf((*MockEpochState)(nil).SetConfigData), arg0, arg1)
}

// SetEpochData mocks base method.
func (m *MockEpochState) SetEpochData(arg0 uint64, arg1 *types.EpochData) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetEpochData", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetEpochData indicates an expected call of SetEpochData.
func (mr *MockEpochStateMockRecorder) SetEpochData(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetEpochData", reflect.TypeOf((*MockEpochState)(nil).SetEpochData), arg0, arg1)
}

// StoreBABENextConfigData mocks base method.
func (m *MockEpochState) StoreBABENextConfigData(arg0 uint64, arg1 common.Hash, arg2 types.NextConfigData) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "StoreBABENextConfigData", arg0, arg1, arg2)
}

// StoreBABENextConfigData indicates an expected call of StoreBABENextConfigData.
func (mr *MockEpochStateMockRecorder) StoreBABENextConfigData(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreBABENextConfigData", reflect.TypeOf((*MockEpochState)(nil).StoreBABENextConfigData), arg0, arg1, arg2)
}

// StoreBABENextEpochData mocks base method.
func (m *MockEpochState) StoreBABENextEpochData(arg0 uint64, arg1 common.Hash, arg2 types.NextEpochData) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "StoreBABENextEpochData", arg0, arg1, arg2)
}

// StoreBABENextEpochData indicates an expected call of StoreBABENextEpochData.
func (mr *MockEpochStateMockRecorder) StoreBABENextEpochData(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreBABENextEpochData", reflect.TypeOf((*MockEpochState)(nil).StoreBABENextEpochData), arg0, arg1, arg2)
}
