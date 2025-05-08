package actors

import (
	"context"
	"encoding/json"
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

const LatestVersion = network.Version26

type ActorCidMap map[string]cid.Cid
type BuiltinActorsMetadata struct {
	Network                   string
	Version                   network.Version
	ActorsNameCidMapByVersion map[network.Version]ActorCidMap
}

type BuiltinActors struct {
	Metadata BuiltinActorsMetadata
}

func NewBuiltinActors(networkName string, loadAllActorVersions bool, lotusApi api.FullNode) (*BuiltinActors, error) {
	networkVersion, err := lotusApi.StateNetworkVersion(context.Background(), types.EmptyTSK)
	if err != nil {
		zap.S().Errorf("could not get lotus network version!: %s", err.Error())
		return nil, err
	}

	actorCids, err := loadActorCids(networkVersion, loadAllActorVersions, lotusApi)
	if err != nil {
		zap.S().Errorf("could not get actors cids!: %s", err.Error())
		return nil, err
	}

	d, _ := json.MarshalIndent(actorCids, "", "  ")
	fmt.Println(string(d))

	metadata := BuiltinActorsMetadata{
		Network:                   string(networkName),
		Version:                   networkVersion,
		ActorsNameCidMapByVersion: actorCids,
	}

	return &BuiltinActors{Metadata: metadata}, nil
}

func (a *BuiltinActors) IsActor(actorCode cid.Cid, actorName string) bool {
	// Try the latest actors' version first
	for _, actors := range a.Metadata.ActorsNameCidMapByVersion {
		if cid, ok := actors[actorName]; ok {
			if actorCode == cid {
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
		if actorCode == code {
			return name, nil
		}
	}

	// Try legacy actors
	name := builtin.ActorNameByCode(actorCode)
	if name != UnknownStr {
		return name, nil
	}

	return UnknownStr, fmt.Errorf("invalid actor code CID: %s", actorCode)
}

func (a *BuiltinActors) GetActorCid(name string) (cid.Cid, error) {
	if cid, ok := a.Metadata.ActorsNameCidMapByVersion[a.Metadata.Version][name]; ok {
		return cid, nil
	}

	return cid.Cid{}, fmt.Errorf("actor '%s' not found in metadata", name)
}

func (a *BuiltinActors) GetActorNameFromCidByVersion(actorCode cid.Cid, version network.Version) (string, error) {
	// Try the latest actors' version first
	for name, code := range a.Metadata.ActorsNameCidMapByVersion[version] {
		if actorCode == code {
			return name, nil
		}
	}

	// Try legacy actors
	name := builtin.ActorNameByCode(actorCode)
	if name != UnknownStr {
		return name, nil
	}

	return UnknownStr, fmt.Errorf("invalid actor code CID: %s", actorCode)
}

func (a *BuiltinActors) GetActorCidByVersion(name string, version network.Version) (cid.Cid, error) {
	if cid, ok := a.Metadata.ActorsNameCidMapByVersion[version][name]; ok {
		return cid, nil
	}

	return cid.Cid{}, fmt.Errorf("actor '%s' not found in metadata", name)
}

func loadActorCids(currentNetworkVersion network.Version, loadAllActorVersions bool, lotusApi api.FullNode) (map[network.Version]ActorCidMap, error) {
	var (
		numWorkers      = 5
		networkVersions []network.Version
		actorCidsMap    = make(map[network.Version]ActorCidMap)
	)

	if loadAllActorVersions {
		zap.S().Info("loading all actor versions")
		networkVersions = make([]network.Version, LatestVersion+1)
		for i := network.Version0; i <= LatestVersion; i++ {
			networkVersions[i] = i
		}
	} else {
		zap.S().Info("loading current actor version")
		networkVersions = []network.Version{currentNetworkVersion}
	}

	versionChannel := make(chan network.Version, len(networkVersions))
	actorCidsChannel := make(chan map[network.Version]ActorCidMap)

	for i := 0; i < numWorkers; i++ {
		go func(i int) {
			for version := range versionChannel {
				fmt.Printf("worker %d: loading actor cids for version %d\n", i, version)
				// todo: retry on network failure
				actorCids, err := lotusApi.StateActorCodeCIDs(context.Background(), version)
				if err != nil {
					zap.S().Errorf("worker %d: error loading actor cids for version %d: %s", i, version, err.Error())
					actorCids = ActorCidMap{}
				}
				actorCidsChannel <- map[network.Version]ActorCidMap{version: actorCids}
			}
		}(i)
	}

	for _, networkVersion := range networkVersions {
		versionChannel <- networkVersion
	}

	var received int
	for actorCids := range actorCidsChannel {
		for version, actors := range actorCids {
			actorCidsMap[version] = actors
		}
		received++
		if received == len(networkVersions) {
			break
		}
	}
	close(versionChannel)
	close(actorCidsChannel)

	return actorCidsMap, nil
}
