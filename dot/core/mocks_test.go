// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ChainSafe/gossamer/dot/core (interfaces: BlockState,StorageState,TransactionState,Network,CodeSubstitutedState,RuntimeInstance,Telemetry)

// Package core is a generated GoMock package.
package core

import (
	json "encoding/json"
	reflect "reflect"

	network "github.com/ChainSafe/gossamer/dot/network"
	peerset "github.com/ChainSafe/gossamer/dot/peerset"
	state "github.com/ChainSafe/gossamer/dot/state"
	types "github.com/ChainSafe/gossamer/dot/types"
	common "github.com/ChainSafe/gossamer/lib/common"
	ed25519 "github.com/ChainSafe/gossamer/lib/crypto/ed25519"
	keystore "github.com/ChainSafe/gossamer/lib/keystore"
	parachaintypes "github.com/ChainSafe/gossamer/lib/parachain-interaction/types"
	runtime "github.com/ChainSafe/gossamer/lib/runtime"
	storage "github.com/ChainSafe/gossamer/lib/runtime/storage"
	transaction "github.com/ChainSafe/gossamer/lib/transaction"
	gomock "github.com/golang/mock/gomock"
	peer "github.com/libp2p/go-libp2p/core/peer"
)

// MockBlockState is a mock of BlockState interface.
type MockBlockState struct {
	ctrl     *gomock.Controller
	recorder *MockBlockStateMockRecorder
}

// MockBlockStateMockRecorder is the mock recorder for MockBlockState.
type MockBlockStateMockRecorder struct {
	mock *MockBlockState
}

// NewMockBlockState creates a new mock instance.
func NewMockBlockState(ctrl *gomock.Controller) *MockBlockState {
	mock := &MockBlockState{ctrl: ctrl}
	mock.recorder = &MockBlockStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBlockState) EXPECT() *MockBlockStateMockRecorder {
	return m.recorder
}

// AddBlock mocks base method.
func (m *MockBlockState) AddBlock(arg0 *types.Block) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddBlock", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddBlock indicates an expected call of AddBlock.
func (mr *MockBlockStateMockRecorder) AddBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBlock", reflect.TypeOf((*MockBlockState)(nil).AddBlock), arg0)
}

// BestBlockHash mocks base method.
func (m *MockBlockState) BestBlockHash() common.Hash {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BestBlockHash")
	ret0, _ := ret[0].(common.Hash)
	return ret0
}

// BestBlockHash indicates an expected call of BestBlockHash.
func (mr *MockBlockStateMockRecorder) BestBlockHash() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BestBlockHash", reflect.TypeOf((*MockBlockState)(nil).BestBlockHash))
}

// BestBlockHeader mocks base method.
func (m *MockBlockState) BestBlockHeader() (*types.Header, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BestBlockHeader")
	ret0, _ := ret[0].(*types.Header)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BestBlockHeader indicates an expected call of BestBlockHeader.
func (mr *MockBlockStateMockRecorder) BestBlockHeader() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BestBlockHeader", reflect.TypeOf((*MockBlockState)(nil).BestBlockHeader))
}

// GetBlockBody mocks base method.
func (m *MockBlockState) GetBlockBody(arg0 common.Hash) (*types.Body, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBlockBody", arg0)
	ret0, _ := ret[0].(*types.Body)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBlockBody indicates an expected call of GetBlockBody.
func (mr *MockBlockStateMockRecorder) GetBlockBody(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBlockBody", reflect.TypeOf((*MockBlockState)(nil).GetBlockBody), arg0)
}

// GetBlockStateRoot mocks base method.
func (m *MockBlockState) GetBlockStateRoot(arg0 common.Hash) (common.Hash, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBlockStateRoot", arg0)
	ret0, _ := ret[0].(common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBlockStateRoot indicates an expected call of GetBlockStateRoot.
func (mr *MockBlockStateMockRecorder) GetBlockStateRoot(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBlockStateRoot", reflect.TypeOf((*MockBlockState)(nil).GetBlockStateRoot), arg0)
}

// GetRuntime mocks base method.
func (m *MockBlockState) GetRuntime(arg0 common.Hash) (state.Runtime, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRuntime", arg0)
	ret0, _ := ret[0].(state.Runtime)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRuntime indicates an expected call of GetRuntime.
func (mr *MockBlockStateMockRecorder) GetRuntime(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRuntime", reflect.TypeOf((*MockBlockState)(nil).GetRuntime), arg0)
}

// HandleRuntimeChanges mocks base method.
func (m *MockBlockState) HandleRuntimeChanges(arg0 *storage.TrieState, arg1 state.Runtime, arg2 common.Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleRuntimeChanges", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleRuntimeChanges indicates an expected call of HandleRuntimeChanges.
func (mr *MockBlockStateMockRecorder) HandleRuntimeChanges(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleRuntimeChanges", reflect.TypeOf((*MockBlockState)(nil).HandleRuntimeChanges), arg0, arg1, arg2)
}

// LowestCommonAncestor mocks base method.
func (m *MockBlockState) LowestCommonAncestor(arg0, arg1 common.Hash) (common.Hash, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LowestCommonAncestor", arg0, arg1)
	ret0, _ := ret[0].(common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LowestCommonAncestor indicates an expected call of LowestCommonAncestor.
func (mr *MockBlockStateMockRecorder) LowestCommonAncestor(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LowestCommonAncestor", reflect.TypeOf((*MockBlockState)(nil).LowestCommonAncestor), arg0, arg1)
}

// RangeInMemory mocks base method.
func (m *MockBlockState) RangeInMemory(arg0, arg1 common.Hash) ([]common.Hash, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RangeInMemory", arg0, arg1)
	ret0, _ := ret[0].([]common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RangeInMemory indicates an expected call of RangeInMemory.
func (mr *MockBlockStateMockRecorder) RangeInMemory(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RangeInMemory", reflect.TypeOf((*MockBlockState)(nil).RangeInMemory), arg0, arg1)
}

// StoreRuntime mocks base method.
func (m *MockBlockState) StoreRuntime(arg0 common.Hash, arg1 state.Runtime) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "StoreRuntime", arg0, arg1)
}

// StoreRuntime indicates an expected call of StoreRuntime.
func (mr *MockBlockStateMockRecorder) StoreRuntime(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreRuntime", reflect.TypeOf((*MockBlockState)(nil).StoreRuntime), arg0, arg1)
}

// MockStorageState is a mock of StorageState interface.
type MockStorageState struct {
	ctrl     *gomock.Controller
	recorder *MockStorageStateMockRecorder
}

// MockStorageStateMockRecorder is the mock recorder for MockStorageState.
type MockStorageStateMockRecorder struct {
	mock *MockStorageState
}

// NewMockStorageState creates a new mock instance.
func NewMockStorageState(ctrl *gomock.Controller) *MockStorageState {
	mock := &MockStorageState{ctrl: ctrl}
	mock.recorder = &MockStorageStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStorageState) EXPECT() *MockStorageStateMockRecorder {
	return m.recorder
}

// GenerateTrieProof mocks base method.
func (m *MockStorageState) GenerateTrieProof(arg0 common.Hash, arg1 [][]byte) ([][]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateTrieProof", arg0, arg1)
	ret0, _ := ret[0].([][]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateTrieProof indicates an expected call of GenerateTrieProof.
func (mr *MockStorageStateMockRecorder) GenerateTrieProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateTrieProof", reflect.TypeOf((*MockStorageState)(nil).GenerateTrieProof), arg0, arg1)
}

// GetStateRootFromBlock mocks base method.
func (m *MockStorageState) GetStateRootFromBlock(arg0 *common.Hash) (*common.Hash, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStateRootFromBlock", arg0)
	ret0, _ := ret[0].(*common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetStateRootFromBlock indicates an expected call of GetStateRootFromBlock.
func (mr *MockStorageStateMockRecorder) GetStateRootFromBlock(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStateRootFromBlock", reflect.TypeOf((*MockStorageState)(nil).GetStateRootFromBlock), arg0)
}

// Lock mocks base method.
func (m *MockStorageState) Lock() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Lock")
}

// Lock indicates an expected call of Lock.
func (mr *MockStorageStateMockRecorder) Lock() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Lock", reflect.TypeOf((*MockStorageState)(nil).Lock))
}

// StoreTrie mocks base method.
func (m *MockStorageState) StoreTrie(arg0 *storage.TrieState, arg1 *types.Header) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreTrie", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreTrie indicates an expected call of StoreTrie.
func (mr *MockStorageStateMockRecorder) StoreTrie(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreTrie", reflect.TypeOf((*MockStorageState)(nil).StoreTrie), arg0, arg1)
}

// TrieState mocks base method.
func (m *MockStorageState) TrieState(arg0 *common.Hash) (*storage.TrieState, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TrieState", arg0)
	ret0, _ := ret[0].(*storage.TrieState)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TrieState indicates an expected call of TrieState.
func (mr *MockStorageStateMockRecorder) TrieState(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TrieState", reflect.TypeOf((*MockStorageState)(nil).TrieState), arg0)
}

// Unlock mocks base method.
func (m *MockStorageState) Unlock() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Unlock")
}

// Unlock indicates an expected call of Unlock.
func (mr *MockStorageStateMockRecorder) Unlock() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unlock", reflect.TypeOf((*MockStorageState)(nil).Unlock))
}

// MockTransactionState is a mock of TransactionState interface.
type MockTransactionState struct {
	ctrl     *gomock.Controller
	recorder *MockTransactionStateMockRecorder
}

// MockTransactionStateMockRecorder is the mock recorder for MockTransactionState.
type MockTransactionStateMockRecorder struct {
	mock *MockTransactionState
}

// NewMockTransactionState creates a new mock instance.
func NewMockTransactionState(ctrl *gomock.Controller) *MockTransactionState {
	mock := &MockTransactionState{ctrl: ctrl}
	mock.recorder = &MockTransactionStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTransactionState) EXPECT() *MockTransactionStateMockRecorder {
	return m.recorder
}

// AddToPool mocks base method.
func (m *MockTransactionState) AddToPool(arg0 *transaction.ValidTransaction) common.Hash {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddToPool", arg0)
	ret0, _ := ret[0].(common.Hash)
	return ret0
}

// AddToPool indicates an expected call of AddToPool.
func (mr *MockTransactionStateMockRecorder) AddToPool(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddToPool", reflect.TypeOf((*MockTransactionState)(nil).AddToPool), arg0)
}

// Exists mocks base method.
func (m *MockTransactionState) Exists(arg0 types.Extrinsic) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exists", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Exists indicates an expected call of Exists.
func (mr *MockTransactionStateMockRecorder) Exists(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockTransactionState)(nil).Exists), arg0)
}

// PendingInPool mocks base method.
func (m *MockTransactionState) PendingInPool() []*transaction.ValidTransaction {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PendingInPool")
	ret0, _ := ret[0].([]*transaction.ValidTransaction)
	return ret0
}

// PendingInPool indicates an expected call of PendingInPool.
func (mr *MockTransactionStateMockRecorder) PendingInPool() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PendingInPool", reflect.TypeOf((*MockTransactionState)(nil).PendingInPool))
}

// Push mocks base method.
func (m *MockTransactionState) Push(arg0 *transaction.ValidTransaction) (common.Hash, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Push", arg0)
	ret0, _ := ret[0].(common.Hash)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Push indicates an expected call of Push.
func (mr *MockTransactionStateMockRecorder) Push(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Push", reflect.TypeOf((*MockTransactionState)(nil).Push), arg0)
}

// RemoveExtrinsic mocks base method.
func (m *MockTransactionState) RemoveExtrinsic(arg0 types.Extrinsic) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RemoveExtrinsic", arg0)
}

// RemoveExtrinsic indicates an expected call of RemoveExtrinsic.
func (mr *MockTransactionStateMockRecorder) RemoveExtrinsic(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveExtrinsic", reflect.TypeOf((*MockTransactionState)(nil).RemoveExtrinsic), arg0)
}

// RemoveExtrinsicFromPool mocks base method.
func (m *MockTransactionState) RemoveExtrinsicFromPool(arg0 types.Extrinsic) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RemoveExtrinsicFromPool", arg0)
}

// RemoveExtrinsicFromPool indicates an expected call of RemoveExtrinsicFromPool.
func (mr *MockTransactionStateMockRecorder) RemoveExtrinsicFromPool(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveExtrinsicFromPool", reflect.TypeOf((*MockTransactionState)(nil).RemoveExtrinsicFromPool), arg0)
}

// MockNetwork is a mock of Network interface.
type MockNetwork struct {
	ctrl     *gomock.Controller
	recorder *MockNetworkMockRecorder
}

// MockNetworkMockRecorder is the mock recorder for MockNetwork.
type MockNetworkMockRecorder struct {
	mock *MockNetwork
}

// NewMockNetwork creates a new mock instance.
func NewMockNetwork(ctrl *gomock.Controller) *MockNetwork {
	mock := &MockNetwork{ctrl: ctrl}
	mock.recorder = &MockNetworkMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNetwork) EXPECT() *MockNetworkMockRecorder {
	return m.recorder
}

// GossipMessage mocks base method.
func (m *MockNetwork) GossipMessage(arg0 network.NotificationsMessage) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GossipMessage", arg0)
}

// GossipMessage indicates an expected call of GossipMessage.
func (mr *MockNetworkMockRecorder) GossipMessage(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GossipMessage", reflect.TypeOf((*MockNetwork)(nil).GossipMessage), arg0)
}

// IsSynced mocks base method.
func (m *MockNetwork) IsSynced() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSynced")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsSynced indicates an expected call of IsSynced.
func (mr *MockNetworkMockRecorder) IsSynced() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSynced", reflect.TypeOf((*MockNetwork)(nil).IsSynced))
}

// ReportPeer mocks base method.
func (m *MockNetwork) ReportPeer(arg0 peerset.ReputationChange, arg1 peer.ID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportPeer", arg0, arg1)
}

// ReportPeer indicates an expected call of ReportPeer.
func (mr *MockNetworkMockRecorder) ReportPeer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportPeer", reflect.TypeOf((*MockNetwork)(nil).ReportPeer), arg0, arg1)
}

// MockCodeSubstitutedState is a mock of CodeSubstitutedState interface.
type MockCodeSubstitutedState struct {
	ctrl     *gomock.Controller
	recorder *MockCodeSubstitutedStateMockRecorder
}

// MockCodeSubstitutedStateMockRecorder is the mock recorder for MockCodeSubstitutedState.
type MockCodeSubstitutedStateMockRecorder struct {
	mock *MockCodeSubstitutedState
}

// NewMockCodeSubstitutedState creates a new mock instance.
func NewMockCodeSubstitutedState(ctrl *gomock.Controller) *MockCodeSubstitutedState {
	mock := &MockCodeSubstitutedState{ctrl: ctrl}
	mock.recorder = &MockCodeSubstitutedStateMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCodeSubstitutedState) EXPECT() *MockCodeSubstitutedStateMockRecorder {
	return m.recorder
}

// StoreCodeSubstitutedBlockHash mocks base method.
func (m *MockCodeSubstitutedState) StoreCodeSubstitutedBlockHash(arg0 common.Hash) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreCodeSubstitutedBlockHash", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreCodeSubstitutedBlockHash indicates an expected call of StoreCodeSubstitutedBlockHash.
func (mr *MockCodeSubstitutedStateMockRecorder) StoreCodeSubstitutedBlockHash(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreCodeSubstitutedBlockHash", reflect.TypeOf((*MockCodeSubstitutedState)(nil).StoreCodeSubstitutedBlockHash), arg0)
}

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

// MockTelemetry is a mock of Telemetry interface.
type MockTelemetry struct {
	ctrl     *gomock.Controller
	recorder *MockTelemetryMockRecorder
}

// MockTelemetryMockRecorder is the mock recorder for MockTelemetry.
type MockTelemetryMockRecorder struct {
	mock *MockTelemetry
}

// NewMockTelemetry creates a new mock instance.
func NewMockTelemetry(ctrl *gomock.Controller) *MockTelemetry {
	mock := &MockTelemetry{ctrl: ctrl}
	mock.recorder = &MockTelemetryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTelemetry) EXPECT() *MockTelemetryMockRecorder {
	return m.recorder
}

// SendMessage mocks base method.
func (m *MockTelemetry) SendMessage(arg0 json.Marshaler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SendMessage", arg0)
}

// SendMessage indicates an expected call of SendMessage.
func (mr *MockTelemetryMockRecorder) SendMessage(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMessage", reflect.TypeOf((*MockTelemetry)(nil).SendMessage), arg0)
}
