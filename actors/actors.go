package actors

import (
	"fmt"
	"github.com/filecoin-project/go-state-types/network"
	"github.com/filecoin-project/lotus/chain/actors/builtin"
	"github.com/ipfs/go-cid"

	// The following import is necessary to ensure that the init() function
	// from the lotus build package is invoked.
	// In a recent refactor (v1.30.0), some build packages were modularized to reduce
	// unnecessary dependencies. As a result, if this package is not explicitly
	// imported, its init() will not be triggered, potentially causing issues
	// with initialization, such as errors when searching for actorNameByCid.
	_ "github.com/filecoin-project/lotus/build"
)

type BuiltinActorsMetadata struct {
	Network          string
	Version          network.Version
	ActorsNameCidMap map[string]cid.Cid
}

type BuiltinActors struct {
	Metadata BuiltinActorsMetadata
}

func (a *BuiltinActors) IsActor(actorCode cid.Cid, actorName string) bool {
	// Try the latest actors' version first
	if a.Metadata.ActorsNameCidMap[actorName] == actorCode {
		return true
	}

	// Try legacy actors
	if IsLegacyActor(actorCode, actorName) {
		return true
	}

	return false
}

func (a *BuiltinActors) GetActorNameFromCid(actorCode cid.Cid) (string, error) {
	// Try the latest actors' version first
	for name, code := range a.Metadata.ActorsNameCidMap {
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
	if cid, ok := a.Metadata.ActorsNameCidMap[name]; ok {
		return cid, nil
	}

	return cid.Cid{}, fmt.Errorf("actor '%s' not found in metadata", name)
}
