package V7

import (
	"github.com/filecoin-project/lotus/chain/actors/builtin"
	builtin7 "github.com/filecoin-project/specs-actors/v7/actors/builtin"
	"github.com/ipfs/go-cid"
	"github.com/zondax/rosetta-filecoin-lib/actors"
	"strings"
)

var (
	// BuiltinActorsKeys NetworkVersion: 15, ActorsVersion: 7
	ActorAccountCode          = builtin7.AccountActorCodeID.String()
	ActorCronCode             = builtin7.CronActorCodeID.String()
	ActorInitCode             = builtin7.InitActorCodeID.String()
	ActorStorageMarketCode    = builtin7.StorageMarketActorCodeID.String()
	ActorStorageMinerCode     = builtin7.StorageMinerActorCodeID.String()
	ActorMultisigCode         = builtin7.MultisigActorCodeID.String()
	ActorPaymentChannelCode   = builtin7.PaymentChannelActorCodeID.String()
	ActorStoragePowerCode     = builtin7.StoragePowerActorCodeID.String()
	ActorRewardCode           = builtin7.RewardActorCodeID.String()
	ActorSystemCode           = builtin7.SystemActorCodeID.String()
	ActorVerifiedRegistryCode = builtin7.VerifiedRegistryActorCodeID.String()
)

var (
	AccountActorCodeID          = builtin7.AccountActorCodeID
	CronActorCodeID             = builtin7.CronActorCodeID
	InitActorCodeID             = builtin7.InitActorCodeID.String()
	StorageMarketActorCodeID    = builtin7.StorageMarketActorCodeID
	StorageMinerActorCodeID     = builtin7.StorageMinerActorCodeID
	MultisigActorCodeID         = builtin7.MultisigActorCodeID
	PaymentChannelActorCodeID   = builtin7.PaymentChannelActorCodeID
	StoragePowerActorCodeID     = builtin7.StoragePowerActorCodeID
	RewardActorCodeID           = builtin7.RewardActorCodeID
	SystemActorCodeID           = builtin7.SystemActorCodeID
	VerifiedRegistryActorCodeID = builtin7.VerifiedRegistryActorCodeID
)

var BuiltinActorsKeys = map[string]string{
	ActorAccountCode:          actors.ActorAccountName,
	ActorCronCode:             actors.ActorCronName,
	ActorInitCode:             actors.ActorInitName,
	ActorStorageMarketCode:    actors.ActorStorageMarketName,
	ActorStorageMinerCode:     actors.ActorStorageMinerName,
	ActorMultisigCode:         actors.ActorMultisigName,
	ActorPaymentChannelCode:   actors.ActorPaymentChannelName,
	ActorStoragePowerCode:     actors.ActorStoragePowerName,
	ActorRewardCode:           actors.ActorRewardName,
	ActorSystemCode:           actors.ActorSystemName,
	ActorVerifiedRegistryCode: actors.ActorVerifiedRegistryName,
}

func IsMultisigActor(actorCode cid.Cid) bool {
	return builtin.IsMultisigActor(actorCode)
}

func GetActorNameFromCid(actorCode cid.Cid) (bool, string) {
	// Check for older actors versions ["fil/<version>/<actorName>"]
	actorName := builtin.ActorNameByCode(actorCode)
	if actorName == actors.UnknownStr {
		return false, actorName
	}

	actorNameArr := strings.Split(actorName, "/")
	actorName = actorNameArr[len(actorNameArr)-1]

	return true, actorName
}
