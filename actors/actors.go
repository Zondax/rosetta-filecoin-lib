package actors

import (
	"fmt"
	"github.com/filecoin-project/lotus/chain/actors/builtin"
	"github.com/ipfs/go-cid"
	actorsCID "github.com/zondax/filecoin-actors-cids/utils"
	"go.uber.org/zap"
)

type BuiltinActors struct {
	Metadata actorsCID.ActorsMetadataMap
}

func (a *BuiltinActors) GetMetadata(network string) error {
	ok, metaLatest := actorsCID.GetMetadataForNetwork(actorsCID.LatestVersion, network)
	if !ok {
		zap.S().Warnf("there's no actors metadata for network '%s' with version '%d'", network, actorsCID.LatestVersion)
	}

	ok, metaPrev := actorsCID.GetMetadataForNetwork(actorsCID.PreviousVersion, network)
	if !ok {
		zap.S().Warnf("there's no actors metadata for network '%s' with version '%d'", network, actorsCID.LatestVersion)
	}

	if len(metaLatest.ActorsNameCidMap) == 0 && len(metaPrev.ActorsNameCidMap) == 0 {
		return fmt.Errorf("could not get any metadata for network '%s'", network)
	}

	a.Metadata = make(actorsCID.ActorsMetadataMap)
	a.Metadata[actorsCID.LatestVersion] = metaLatest
	a.Metadata[actorsCID.PreviousVersion] = metaPrev

	return nil
}

func (a *BuiltinActors) IsActor(actorCode cid.Cid, actorName string) bool {
	// Try the latest actors' version first
	if a.Metadata.GetActorCid(actorsCID.LatestVersion, actorName) == actorCode {
		return true
	}

	// Try the previous actors' version
	if a.Metadata.GetActorCid(actorsCID.PreviousVersion, actorName) == actorCode {
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
	if ok, name := a.Metadata.GetActorName(actorsCID.LatestVersion, actorCode); ok {
		return name, nil
	}

	// Try the previous actors' version
	if ok, name := a.Metadata.GetActorName(actorsCID.PreviousVersion, actorCode); ok {
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
	return a.Metadata.GetActorCid(version, name)
}
