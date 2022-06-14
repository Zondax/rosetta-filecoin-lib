package builtin

import (
	"fmt"
	"github.com/ipfs/go-cid"
	"github.com/zondax/rosetta-filecoin-lib/actors"
	"github.com/zondax/rosetta-filecoin-lib/actors/builtin/V7"
	"github.com/zondax/rosetta-filecoin-lib/actors/builtin/V8"
)

func IsActor(actorCode cid.Cid, actorName string) bool {
	if V8.IsActor(actorCode, actorName) {
		return true
	}

	if V7.IsActor(actorCode, actorName) {
		return true
	}

	return false
}

func GetActorNameFromCid(actorCode cid.Cid) (string, error) {
	ok, actorName := V8.GetActorNameFromCid(actorCode)
	if ok {
		return actorName, nil
	}

	ok, actorName = V7.GetActorNameFromCid(actorCode)
	if ok {
		return actorName, nil
	}

	return actors.UnknownStr, fmt.Errorf("invalid actor code CID: %s", actorCode)
}
