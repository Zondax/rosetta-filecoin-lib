package actors

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/filecoin-project/go-state-types/network"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/actors/builtin"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/ipfs/go-cid"
	"go.uber.org/zap"

	// The following import is necessary to ensure that the init() function
	// from the lotus build package is invoked.
	// In a recent refactor (v1.30.0), some build packages were modularized to reduce
	// unnecessary dependencies. As a result, if this package is not explicitly
	// imported, its init() will not be triggered, potentially causing issues
	// with initialization, such as errors when searching for actorNameByCid.
	_ "github.com/filecoin-project/lotus/build"
)

const LatestVersion = network.Version29

type ActorCidMap map[string]cid.Cid
type BuiltinActorsMetadata struct {
	Network                   string
	Version                   network.Version
	ActorsNameCidMapByVersion map[network.Version]ActorCidMap
}

type BuiltinActors struct {
	Metadata BuiltinActorsMetadata
}

func NewBuiltinActors(networkName string, lotusApi api.FullNode) (*BuiltinActors, error) {
	networkVersion, err := lotusApi.StateNetworkVersion(context.Background(), types.EmptyTSK)
	if err != nil {
		zap.S().Errorf("could not get lotus network version!: %s", err.Error())
		return nil, err
	}

	actorCids, err := loadActorCids(lotusApi)
	if err != nil {
		zap.S().Errorf("could not get actors cids!: %s", err.Error())
		return nil, err
	}

	metadata := BuiltinActorsMetadata{
		Network:                   string(networkName),
		Version:                   networkVersion,
		ActorsNameCidMapByVersion: actorCids,
	}

	return &BuiltinActors{Metadata: metadata}, nil
}

func (a *BuiltinActors) IsActor(actorCode cid.Cid, actorName string) bool {
	// Try the latest actors' version first
	for _, actorCids := range a.Metadata.ActorsNameCidMapByVersion {
		if cid, ok := actorCids[actorName]; ok {
			if actorCode.String() == cid.String() {
				return true
			}
		}
	}

	// Try legacy actors
	if IsLegacyActor(actorCode, actorName) {
		return true
	}

	return false
}

func (a *BuiltinActors) GetActorNameFromCid(actorCode cid.Cid) (string, error) {
	// Try the latest actors' version first
	for name, code := range a.Metadata.ActorsNameCidMapByVersion[a.Metadata.Version] {
		if actorCode.String() == code.String() {
			return name, nil
		}
	}

	// Try legacy actors
	name := builtin.ActorNameByCode(actorCode)
	if name != UnknownStr {
		return name, nil
	}

	// Fallback: Check all actors
	return a.getActorNameFromCidByVersionFallback(actorCode)
}

func (a *BuiltinActors) GetActorCid(name string) (cid.Cid, error) {
	if cid, ok := a.Metadata.ActorsNameCidMapByVersion[a.Metadata.Version][name]; ok {
		return cid, nil
	}

	// Fallback: Check all actors
	return a.getActorCidByVersionFallback(name)
}

func (a *BuiltinActors) GetActorNameFromCidByVersion(actorCode cid.Cid, version network.Version) (string, error) {
	// Try the latest actors' version first
	for name, code := range a.Metadata.ActorsNameCidMapByVersion[version] {
		if actorCode.String() == code.String() {
			return name, nil
		}
	}

	// Try legacy actors
	name := builtin.ActorNameByCode(actorCode)
	if name != UnknownStr {
		return name, nil
	}

	// Fallback: Check all actors
	return a.getActorNameFromCidByVersionFallback(actorCode)
}

func (a *BuiltinActors) GetActorCidByVersion(name string, version network.Version) (cid.Cid, error) {
	if cid, ok := a.Metadata.ActorsNameCidMapByVersion[version][name]; ok {
		return cid, nil
	}
	// Fallback: Check all actors
	return a.getActorCidByVersionFallback(name)
}

func (a *BuiltinActors) getActorCidByVersionFallback(name string) (cid.Cid, error) {
	for _, actorCids := range a.Metadata.ActorsNameCidMapByVersion {
		for foundName, cid := range actorCids {
			if foundName == name {
				return cid, nil
			}
		}
	}
	return cid.Cid{}, fmt.Errorf("actor '%s' not found in metadata", name)
}

func (a *BuiltinActors) getActorNameFromCidByVersionFallback(actorCode cid.Cid) (string, error) {
	for _, actorCids := range a.Metadata.ActorsNameCidMapByVersion {
		for name, cid := range actorCids {
			if actorCode.String() == cid.String() {
				return name, nil
			}
		}
	}
	return UnknownStr, fmt.Errorf("invalid actor code CID: %s", actorCode)
}

// errUnsupportedNetworkVersion is the text lotus returns from StateActorCodeCIDs for a network
// version it does not know yet (go-state-types actors.VersionForNetwork).
const errUnsupportedNetworkVersion = "unsupported network version"

// loadActorCids fetches the actor code CIDs for every network version up to LatestVersion.
//
// A node that predates a network version answers "unsupported network version" for it; that
// version is skipped with a warning instead of failing the whole load. This keeps the library
// usable against nodes that have not upgraded yet (e.g. mainnet while an upgrade is only scheduled
// on calibration): such a node has no chain data at the unknown version, so nothing is lost. Any
// other error is still fatal.
func loadActorCids(lotusApi api.FullNode) (map[network.Version]ActorCidMap, error) {
	zap.S().Info("loading all actor versions")
	const numWorkers = 5

	type result struct {
		version network.Version
		cids    ActorCidMap
		err     error
	}

	versions := make(chan network.Version, LatestVersion+1)
	for v := network.Version0; v <= LatestVersion; v++ {
		versions <- v
	}
	close(versions)

	// Buffered for every version, so workers never block and nothing is sent on a closed channel.
	results := make(chan result, LatestVersion+1)
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for version := range versions {
				// todo: retry on network failure
				cids, err := lotusApi.StateActorCodeCIDs(context.Background(), version)
				results <- result{version: version, cids: cids, err: err}
			}
		}()
	}
	wg.Wait()
	close(results)

	actorCidsMap := make(map[network.Version]ActorCidMap)
	for r := range results {
		switch {
		case r.err == nil:
			actorCidsMap[r.version] = r.cids
		case strings.Contains(r.err.Error(), errUnsupportedNetworkVersion):
			zap.S().Warnf("node does not support network version %d yet, skipping its actor cids: %s", r.version, r.err.Error())
		default:
			zap.S().Errorf("error loading actor cids for version %d: %s", r.version, r.err.Error())
			return nil, fmt.Errorf("loading actor cids for network version %d: %w", r.version, r.err)
		}
	}

	return actorCidsMap, nil
}
