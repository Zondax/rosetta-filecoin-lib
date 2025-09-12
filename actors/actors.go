package actors

import (
	"context"
	"fmt"

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

const LatestVersion = network.Version27

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

func loadActorCids(lotusApi api.FullNode) (map[network.Version]ActorCidMap, error) {
	zap.S().Info("loading all actor versions")
	var (
		numWorkers      = 5
		networkVersions = make([]network.Version, LatestVersion+1)
		actorCidsMap    = make(map[network.Version]ActorCidMap)
	)

	for i := network.Version0; i <= LatestVersion; i++ {
		networkVersions[i] = i
	}

	versionChannel := make(chan network.Version, len(networkVersions))
	actorCidsChannel := make(chan map[network.Version]ActorCidMap)
	errChannel := make(chan error)

	for i := 0; i < numWorkers; i++ {
		go func(i int) {
			for version := range versionChannel {
				// todo: retry on network failure
				actorCids, err := lotusApi.StateActorCodeCIDs(context.Background(), version)
				if err != nil {
					zap.S().Errorf("worker %d: error loading actor cids for version %d: %s", i, version, err.Error())
					errChannel <- err
					return
				}
				actorCidsChannel <- map[network.Version]ActorCidMap{version: actorCids}
			}
		}(i)
	}

	for _, networkVersion := range networkVersions {
		versionChannel <- networkVersion
	}

	var received int
	var err error
	for {
		select {
		case actorCids := <-actorCidsChannel:
			for version, actors := range actorCids {
				actorCidsMap[version] = actors
			}
			received++

		case mErr := <-errChannel:
			err = mErr
		}

		if received == len(networkVersions) || err != nil {
			break
		}
	}

	close(versionChannel)
	close(errChannel)
	close(actorCidsChannel)

	if err != nil {
		return nil, err
	}

	return actorCidsMap, nil
}
