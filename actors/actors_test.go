package actors

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/filecoin-project/go-state-types/network"
	"github.com/filecoin-project/lotus/api"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

// fakeNode answers StateActorCodeCIDs from a fixed error table; every other FullNode method is
// left nil and must not be called by loadActorCids.
type fakeNode struct {
	api.FullNode
	errs map[network.Version]error
}

func (f fakeNode) StateActorCodeCIDs(_ context.Context, v network.Version) (map[string]cid.Cid, error) {
	if err, ok := f.errs[v]; ok {
		return nil, err
	}
	return map[string]cid.Cid{fmt.Sprintf("actor-v%d", v): cid.Undef}, nil
}

// unsupported is the error a node that predates a network version returns over RPC.
func unsupported(v network.Version) error {
	return fmt.Errorf("invalid network version %d: unsupported network version %d", v, v)
}

func TestLoadActorCids(t *testing.T) {
	t.Run("all versions load", func(t *testing.T) {
		got, err := loadActorCids(fakeNode{})
		require.NoError(t, err)
		require.Len(t, got, int(LatestVersion)+1)
	})

	t.Run("a version the node does not know yet is skipped", func(t *testing.T) {
		got, err := loadActorCids(fakeNode{errs: map[network.Version]error{LatestVersion: unsupported(LatestVersion)}})
		require.NoError(t, err)
		require.Len(t, got, int(LatestVersion))
		require.NotContains(t, got, LatestVersion)
		require.Contains(t, got, LatestVersion-1)
	})

	t.Run("any other error still fails the load", func(t *testing.T) {
		_, err := loadActorCids(fakeNode{errs: map[network.Version]error{network.Version5: errors.New("connection refused")}})
		require.ErrorContains(t, err, "network version 5")
		require.ErrorContains(t, err, "connection refused")
	})

	t.Run("errors on several versions do not deadlock or panic", func(t *testing.T) {
		errs := map[network.Version]error{}
		for v := network.Version0; v <= LatestVersion; v++ {
			errs[v] = errors.New("boom")
		}
		_, err := loadActorCids(fakeNode{errs: errs})
		require.Error(t, err)
	})
}
