// Copyright 2024 ChainSafe Systems (ON)
// SPDX-License-Identifier: LGPL-3.0-only

package sync

import (
	"sync"

	"github.com/ChainSafe/gossamer/lib/common"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/exp/maps"
)

type peerView struct {
	bestBlockNumber uint32
	bestBlockHash   common.Hash
}

type peerViewSet struct {
	mtx    sync.RWMutex
	view   map[peer.ID]peerView
	target uint32
}

func (p *peerViewSet) update(peerID peer.ID, bestHash common.Hash, bestNumber uint32) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	newView := peerView{
		bestBlockHash:   bestHash,
		bestBlockNumber: bestNumber,
	}

	view, ok := p.view[peerID]
	if ok && view.bestBlockNumber >= newView.bestBlockNumber {
		return
	}

	logger.Infof("updating peer %s view to #%d (%s)", peerID.String(), bestNumber, bestHash.Short())
	p.view[peerID] = newView
}

// getTarget takes the average of all peer views best number
func (p *peerViewSet) getTarget() uint32 {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if len(p.view) == 0 {
		return p.target
	}

	currMax := p.target
	// we are going to sort the data and remove the outliers then we will return the avg of all the valid elements
	for _, view := range maps.Values(p.view) {
		if view.bestBlockNumber > currMax {
			currMax = view.bestBlockNumber
		}
	}

	p.target = currMax // cache latest calculated target
	return p.target
}
