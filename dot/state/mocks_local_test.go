// Code generated by MockGen. DO NOT EDIT.
// Source: interfaces_mock_source.go

// Package state is a generated GoMock package.
package state

import (
	reflect "reflect"

	chaindb "github.com/ChainSafe/chaindb"
	gomock "github.com/golang/mock/gomock"
)

// MockblockStateDatabase is a mock of blockStateDatabase interface.
type MockblockStateDatabase struct {
	ctrl     *gomock.Controller
	recorder *MockblockStateDatabaseMockRecorder
}

// MockblockStateDatabaseMockRecorder is the mock recorder for MockblockStateDatabase.
type MockblockStateDatabaseMockRecorder struct {
	mock *MockblockStateDatabase
}

// NewMockblockStateDatabase creates a new mock instance.
func NewMockblockStateDatabase(ctrl *gomock.Controller) *MockblockStateDatabase {
	mock := &MockblockStateDatabase{ctrl: ctrl}
	mock.recorder = &MockblockStateDatabaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockblockStateDatabase) EXPECT() *MockblockStateDatabaseMockRecorder {
	return m.recorder
}

// Del mocks base method.
func (m *MockblockStateDatabase) Del(key []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Del", key)
	ret0, _ := ret[0].(error)
	return ret0
}

// Del indicates an expected call of Del.
func (mr *MockblockStateDatabaseMockRecorder) Del(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Del", reflect.TypeOf((*MockblockStateDatabase)(nil).Del), key)
}

// Get mocks base method.
func (m *MockblockStateDatabase) Get(key []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", key)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockblockStateDatabaseMockRecorder) Get(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockblockStateDatabase)(nil).Get), key)
}

// Has mocks base method.
func (m *MockblockStateDatabase) Has(key []byte) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Has", key)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Has indicates an expected call of Has.
func (mr *MockblockStateDatabaseMockRecorder) Has(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Has", reflect.TypeOf((*MockblockStateDatabase)(nil).Has), key)
}

// NewBatch mocks base method.
func (m *MockblockStateDatabase) NewBatch() chaindb.Batch {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewBatch")
	ret0, _ := ret[0].(chaindb.Batch)
	return ret0
}

// NewBatch indicates an expected call of NewBatch.
func (mr *MockblockStateDatabaseMockRecorder) NewBatch() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewBatch", reflect.TypeOf((*MockblockStateDatabase)(nil).NewBatch))
}

// Put mocks base method.
func (m *MockblockStateDatabase) Put(key, value []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Put", key, value)
	ret0, _ := ret[0].(error)
	return ret0
}

// Put indicates an expected call of Put.
func (mr *MockblockStateDatabaseMockRecorder) Put(key, value interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockblockStateDatabase)(nil).Put), key, value)
}