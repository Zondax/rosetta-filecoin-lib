package builtin

import (
	"fmt"
	"github.com/ipfs/go-cid"
	"github.com/zondax/rosetta-filecoin-lib/actors"
	"github.com/zondax/rosetta-filecoin-lib/actors/builtin/V7"
	"github.com/zondax/rosetta-filecoin-lib/actors/builtin/V8"
)

func IsMultisigActor(actorCode cid.Cid) bool {
	if V8.IsMultisigActor(actorCode) {
		return true
	}

	if V7.IsMultisigActor(actorCode) {
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
