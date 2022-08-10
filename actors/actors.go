package actors

import (
	"fmt"
	"github.com/filecoin-project/lotus/chain/actors/builtin"
	"github.com/ipfs/go-cid"
	actorsCID "github.com/zondax/filecoin-actors-cids/utils"
)

type BuiltinActors struct {
	metadata actorsCID.ActorsMetadataMap
}

func (a *BuiltinActors) GetMetadata(network string) error {
	ok, metaLatest := actorsCID.GetMetadataForNetwork(actorsCID.ActorsV8, network)
	if !ok {
		return fmt.Errorf("network and/or version are invalid")
	}

	ok, metaPrev := actorsCID.GetMetadataForNetwork(actorsCID.ActorsV7, network)
	if !ok {
		return fmt.Errorf("network and/or version are invalid")
	}

	a.metadata = make(actorsCID.ActorsMetadataMap)
	a.metadata[actorsCID.ActorsV8] = metaLatest
	a.metadata[actorsCID.ActorsV7] = metaPrev

	return nil
}

func (a *BuiltinActors) IsActor(actorCode cid.Cid, actorName string) bool {
	// Try the latest actors' version first
	if a.metadata.GetActorCid(actorsCID.ActorsV8, actorName) == actorCode {
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
	if ok, name := a.metadata.GetActorName(actorsCID.ActorsV8, actorCode); ok {
		return name, nil
	}

	// Try legacy actors
	name := builtin.ActorNameByCode(actorCode)
	if name != UnknownStr {
		return name, nil
	}

	return UnknownStr, fmt.Errorf("invalid actor code CID: %s", actorCode)
}

func (a *BuiltinActors) GetActorCid(version uint, name string) cid.Cid {
	return a.metadata.GetActorCid(version, name)
}
