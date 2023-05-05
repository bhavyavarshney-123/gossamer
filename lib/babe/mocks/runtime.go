// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/core (interfaces: RuntimeInstance)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	types "github.com/ChainSafe/gossamer/dot/types"
	common "github.com/ChainSafe/gossamer/lib/common"
	ed25519 "github.com/ChainSafe/gossamer/lib/crypto/ed25519"
	keystore "github.com/ChainSafe/gossamer/lib/keystore"
	parachaintypes "github.com/ChainSafe/gossamer/lib/parachain-interaction/types"
	runtime "github.com/ChainSafe/gossamer/lib/runtime"
	transaction "github.com/ChainSafe/gossamer/lib/transaction"
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

// ApplyExtrinsic mocks base method.
func (m *MockRuntimeInstance) ApplyExtrinsic(arg0 types.Extrinsic) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ApplyExtrinsic", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ApplyExtrinsic indicates an expected call of ApplyExtrinsic.
func (mr *MockRuntimeInstanceMockRecorder) ApplyExtrinsic(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ApplyExtrinsic", reflect.TypeOf((*MockRuntimeInstance)(nil).ApplyExtrinsic), arg0)
}

// BabeConfiguration mocks base method.
func (m *MockRuntimeInstance) BabeConfiguration() (*types.BabeConfiguration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BabeConfiguration")
	ret0, _ := ret[0].(*types.BabeConfiguration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BabeConfiguration indicates an expected call of BabeConfiguration.
func (mr *MockRuntimeInstanceMockRecorder) BabeConfiguration() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BabeConfiguration", reflect.TypeOf((*MockRuntimeInstance)(nil).BabeConfiguration))
}

// BabeGenerateKeyOwnershipProof mocks base method.
func (m *MockRuntimeInstance) BabeGenerateKeyOwnershipProof(arg0 uint64, arg1 [32]byte) (types.OpaqueKeyOwnershipProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BabeGenerateKeyOwnershipProof", arg0, arg1)
	ret0, _ := ret[0].(types.OpaqueKeyOwnershipProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BabeGenerateKeyOwnershipProof indicates an expected call of BabeGenerateKeyOwnershipProof.
func (mr *MockRuntimeInstanceMockRecorder) BabeGenerateKeyOwnershipProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BabeGenerateKeyOwnershipProof", reflect.TypeOf((*MockRuntimeInstance)(nil).BabeGenerateKeyOwnershipProof), arg0, arg1)
}

// BabeSubmitReportEquivocationUnsignedExtrinsic mocks base method.
func (m *MockRuntimeInstance) BabeSubmitReportEquivocationUnsignedExtrinsic(arg0 types.BabeEquivocationProof, arg1 types.OpaqueKeyOwnershipProof) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BabeSubmitReportEquivocationUnsignedExtrinsic", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// BabeSubmitReportEquivocationUnsignedExtrinsic indicates an expected call of BabeSubmitReportEquivocationUnsignedExtrinsic.
func (mr *MockRuntimeInstanceMockRecorder) BabeSubmitReportEquivocationUnsignedExtrinsic(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BabeSubmitReportEquivocationUnsignedExtrinsic", reflect.TypeOf((*MockRuntimeInstance)(nil).BabeSubmitReportEquivocationUnsignedExtrinsic), arg0, arg1)
}

// CheckInherents mocks base method.
func (m *MockRuntimeInstance) CheckInherents() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CheckInherents")
}

// CheckInherents indicates an expected call of CheckInherents.
func (mr *MockRuntimeInstanceMockRecorder) CheckInherents() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckInherents", reflect.TypeOf((*MockRuntimeInstance)(nil).CheckInherents))
}

// DecodeSessionKeys mocks base method.
func (m *MockRuntimeInstance) DecodeSessionKeys(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecodeSessionKeys", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DecodeSessionKeys indicates an expected call of DecodeSessionKeys.
func (mr *MockRuntimeInstanceMockRecorder) DecodeSessionKeys(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecodeSessionKeys", reflect.TypeOf((*MockRuntimeInstance)(nil).DecodeSessionKeys), arg0)
}

// Exec mocks base method.
func (m *MockRuntimeInstance) Exec(arg0 string, arg1 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exec", arg0, arg1)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exec indicates an expected call of Exec.
func (mr *MockRuntimeInstanceMockRecorder) Exec(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exec", reflect.TypeOf((*MockRuntimeInstance)(nil).Exec), arg0, arg1)
}

// ExecuteBlock mocks base method.
func (m *MockRuntimeInstance) ExecuteBlock(arg0 *types.Block) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecuteBlock", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExecuteBlock indicates an expected call of ExecuteBlock.
func (mr *MockRuntimeInstanceMockRecorder) ExecuteBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecuteBlock", reflect.TypeOf((*MockRuntimeInstance)(nil).ExecuteBlock), arg0)
}

// FinalizeBlock mocks base method.
func (m *MockRuntimeInstance) FinalizeBlock() (*types.Header, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FinalizeBlock")
	ret0, _ := ret[0].(*types.Header)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FinalizeBlock indicates an expected call of FinalizeBlock.
func (mr *MockRuntimeInstanceMockRecorder) FinalizeBlock() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FinalizeBlock", reflect.TypeOf((*MockRuntimeInstance)(nil).FinalizeBlock))
}

// GenerateSessionKeys mocks base method.
func (m *MockRuntimeInstance) GenerateSessionKeys() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GenerateSessionKeys")
}

// GenerateSessionKeys indicates an expected call of GenerateSessionKeys.
func (mr *MockRuntimeInstanceMockRecorder) GenerateSessionKeys() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateSessionKeys", reflect.TypeOf((*MockRuntimeInstance)(nil).GenerateSessionKeys))
}

// GetCodeHash mocks base method.
func (m *MockRuntimeInstance) GetCodeHash() common.Hash {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCodeHash")
	ret0, _ := ret[0].(common.Hash)
	return ret0
}

// GetCodeHash indicates an expected call of GetCodeHash.
func (mr *MockRuntimeInstanceMockRecorder) GetCodeHash() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCodeHash", reflect.TypeOf((*MockRuntimeInstance)(nil).GetCodeHash))
}

// GrandpaAuthorities mocks base method.
func (m *MockRuntimeInstance) GrandpaAuthorities() ([]types.Authority, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GrandpaAuthorities")
	ret0, _ := ret[0].([]types.Authority)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GrandpaAuthorities indicates an expected call of GrandpaAuthorities.
func (mr *MockRuntimeInstanceMockRecorder) GrandpaAuthorities() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrandpaAuthorities", reflect.TypeOf((*MockRuntimeInstance)(nil).GrandpaAuthorities))
}

// GrandpaGenerateKeyOwnershipProof mocks base method.
func (m *MockRuntimeInstance) GrandpaGenerateKeyOwnershipProof(arg0 uint64, arg1 ed25519.PublicKeyBytes) (types.GrandpaOpaqueKeyOwnershipProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GrandpaGenerateKeyOwnershipProof", arg0, arg1)
	ret0, _ := ret[0].(types.GrandpaOpaqueKeyOwnershipProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GrandpaGenerateKeyOwnershipProof indicates an expected call of GrandpaGenerateKeyOwnershipProof.
func (mr *MockRuntimeInstanceMockRecorder) GrandpaGenerateKeyOwnershipProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrandpaGenerateKeyOwnershipProof", reflect.TypeOf((*MockRuntimeInstance)(nil).GrandpaGenerateKeyOwnershipProof), arg0, arg1)
}

// GrandpaSubmitReportEquivocationUnsignedExtrinsic mocks base method.
func (m *MockRuntimeInstance) GrandpaSubmitReportEquivocationUnsignedExtrinsic(arg0 types.GrandpaEquivocationProof, arg1 types.GrandpaOpaqueKeyOwnershipProof) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GrandpaSubmitReportEquivocationUnsignedExtrinsic", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// GrandpaSubmitReportEquivocationUnsignedExtrinsic indicates an expected call of GrandpaSubmitReportEquivocationUnsignedExtrinsic.
func (mr *MockRuntimeInstanceMockRecorder) GrandpaSubmitReportEquivocationUnsignedExtrinsic(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrandpaSubmitReportEquivocationUnsignedExtrinsic", reflect.TypeOf((*MockRuntimeInstance)(nil).GrandpaSubmitReportEquivocationUnsignedExtrinsic), arg0, arg1)
}

// InherentExtrinsics mocks base method.
func (m *MockRuntimeInstance) InherentExtrinsics(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InherentExtrinsics", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InherentExtrinsics indicates an expected call of InherentExtrinsics.
func (mr *MockRuntimeInstanceMockRecorder) InherentExtrinsics(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InherentExtrinsics", reflect.TypeOf((*MockRuntimeInstance)(nil).InherentExtrinsics), arg0)
}

// InitializeBlock mocks base method.
func (m *MockRuntimeInstance) InitializeBlock(arg0 *types.Header) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitializeBlock", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// InitializeBlock indicates an expected call of InitializeBlock.
func (mr *MockRuntimeInstanceMockRecorder) InitializeBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitializeBlock", reflect.TypeOf((*MockRuntimeInstance)(nil).InitializeBlock), arg0)
}

// Keystore mocks base method.
func (m *MockRuntimeInstance) Keystore() *keystore.GlobalKeystore {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Keystore")
	ret0, _ := ret[0].(*keystore.GlobalKeystore)
	return ret0
}

// Keystore indicates an expected call of Keystore.
func (mr *MockRuntimeInstanceMockRecorder) Keystore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Keystore", reflect.TypeOf((*MockRuntimeInstance)(nil).Keystore))
}

// Metadata mocks base method.
func (m *MockRuntimeInstance) Metadata() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Metadata")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Metadata indicates an expected call of Metadata.
func (mr *MockRuntimeInstanceMockRecorder) Metadata() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Metadata", reflect.TypeOf((*MockRuntimeInstance)(nil).Metadata))
}

// NetworkService mocks base method.
func (m *MockRuntimeInstance) NetworkService() runtime.BasicNetwork {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NetworkService")
	ret0, _ := ret[0].(runtime.BasicNetwork)
	return ret0
}

// NetworkService indicates an expected call of NetworkService.
func (mr *MockRuntimeInstanceMockRecorder) NetworkService() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NetworkService", reflect.TypeOf((*MockRuntimeInstance)(nil).NetworkService))
}

// NodeStorage mocks base method.
func (m *MockRuntimeInstance) NodeStorage() runtime.NodeStorage {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NodeStorage")
	ret0, _ := ret[0].(runtime.NodeStorage)
	return ret0
}

// NodeStorage indicates an expected call of NodeStorage.
func (mr *MockRuntimeInstanceMockRecorder) NodeStorage() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NodeStorage", reflect.TypeOf((*MockRuntimeInstance)(nil).NodeStorage))
}

// OffchainWorker mocks base method.
func (m *MockRuntimeInstance) OffchainWorker() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OffchainWorker")
}

// OffchainWorker indicates an expected call of OffchainWorker.
func (mr *MockRuntimeInstanceMockRecorder) OffchainWorker() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OffchainWorker", reflect.TypeOf((*MockRuntimeInstance)(nil).OffchainWorker))
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

// PaymentQueryInfo mocks base method.
func (m *MockRuntimeInstance) PaymentQueryInfo(arg0 []byte) (*types.RuntimeDispatchInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PaymentQueryInfo", arg0)
	ret0, _ := ret[0].(*types.RuntimeDispatchInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PaymentQueryInfo indicates an expected call of PaymentQueryInfo.
func (mr *MockRuntimeInstanceMockRecorder) PaymentQueryInfo(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PaymentQueryInfo", reflect.TypeOf((*MockRuntimeInstance)(nil).PaymentQueryInfo), arg0)
}

// RandomSeed mocks base method.
func (m *MockRuntimeInstance) RandomSeed() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RandomSeed")
}

// RandomSeed indicates an expected call of RandomSeed.
func (mr *MockRuntimeInstanceMockRecorder) RandomSeed() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RandomSeed", reflect.TypeOf((*MockRuntimeInstance)(nil).RandomSeed))
}

// SetContextStorage mocks base method.
func (m *MockRuntimeInstance) SetContextStorage(arg0 runtime.Storage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetContextStorage", arg0)
}

// SetContextStorage indicates an expected call of SetContextStorage.
func (mr *MockRuntimeInstanceMockRecorder) SetContextStorage(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetContextStorage", reflect.TypeOf((*MockRuntimeInstance)(nil).SetContextStorage), arg0)
}

// Stop mocks base method.
func (m *MockRuntimeInstance) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockRuntimeInstanceMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockRuntimeInstance)(nil).Stop))
}

// ValidateTransaction mocks base method.
func (m *MockRuntimeInstance) ValidateTransaction(arg0 types.Extrinsic) (*transaction.Validity, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateTransaction", arg0)
	ret0, _ := ret[0].(*transaction.Validity)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateTransaction indicates an expected call of ValidateTransaction.
func (mr *MockRuntimeInstanceMockRecorder) ValidateTransaction(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateTransaction", reflect.TypeOf((*MockRuntimeInstance)(nil).ValidateTransaction), arg0)
}

// Validator mocks base method.
func (m *MockRuntimeInstance) Validator() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validator")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Validator indicates an expected call of Validator.
func (mr *MockRuntimeInstanceMockRecorder) Validator() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validator", reflect.TypeOf((*MockRuntimeInstance)(nil).Validator))
}

// Version mocks base method.
func (m *MockRuntimeInstance) Version() (runtime.Version, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Version")
	ret0, _ := ret[0].(runtime.Version)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Version indicates an expected call of Version.
func (mr *MockRuntimeInstanceMockRecorder) Version() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Version", reflect.TypeOf((*MockRuntimeInstance)(nil).Version))
}
