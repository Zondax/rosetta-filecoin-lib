package actors

import (
	"github.com/filecoin-project/go-state-types/manifest"
	builtin0 "github.com/filecoin-project/specs-actors/actors/builtin"
	builtin2 "github.com/filecoin-project/specs-actors/v2/actors/builtin"
	builtin3 "github.com/filecoin-project/specs-actors/v3/actors/builtin"
	builtin4 "github.com/filecoin-project/specs-actors/v4/actors/builtin"
	builtin5 "github.com/filecoin-project/specs-actors/v5/actors/builtin"
	builtin6 "github.com/filecoin-project/specs-actors/v6/actors/builtin"
	builtin7 "github.com/filecoin-project/specs-actors/v7/actors/builtin"
	builtin8 "github.com/filecoin-project/specs-actors/v8/actors/builtin"
	"github.com/ipfs/go-cid"
	"go.uber.org/zap"
)

func IsLegacyActor(actorCode cid.Cid, actorName string) bool {
	switch actorName {
	case manifest.InitKey:
		return IsLegacyInitActor(actorCode)
	case manifest.SystemKey:
		return IsLegacySystemActor(actorCode)
	case manifest.CronKey:
		return IsLegacyCronActor(actorCode)
	case manifest.PowerKey:
		return IsLegacyStoragePowerActor(actorCode)
	case manifest.MinerKey:
		return IsLegacyStorageMinerActor(actorCode)
	case manifest.MarketKey:
		return IsLegacyStorageMarketActor(actorCode)
	case manifest.PaychKey:
		return IsLegacyPaymentChannelActor(actorCode)
	case manifest.RewardKey:
		return IsLegacyRewardActor(actorCode)
	case manifest.VerifregKey:
		return IsLegacyVerifiedRegistryActor(actorCode)
	case manifest.AccountKey:
		return IsLegacyAccountActor(actorCode)
	case manifest.MultisigKey:
		return IsLegacyMultisigActor(actorCode)
	default:
		zap.S().Errorf("could not find a legacy actor '%s' with cid '%s'", actorName, actorCode.String())
		return false
	}
}

func IsLegacyMultisigActor(c cid.Cid) bool {
	if c == builtin0.MultisigActorCodeID {
		return true
	}

	if c == builtin2.MultisigActorCodeID {
		return true
	}

	if c == builtin3.MultisigActorCodeID {
		return true
	}

	if c == builtin4.MultisigActorCodeID {
		return true
	}

	if c == builtin5.MultisigActorCodeID {
		return true
	}

	if c == builtin6.MultisigActorCodeID {
		return true
	}

	if c == builtin7.MultisigActorCodeID {
		return true
	}

	if c == builtin8.MultisigActorCodeID {
		return true
	}

	return false
}

func IsLegacyAccountActor(c cid.Cid) bool {
	if c == builtin0.AccountActorCodeID {
		return true
	}

	if c == builtin2.AccountActorCodeID {
		return true
	}

	if c == builtin3.AccountActorCodeID {
		return true
	}

	if c == builtin4.AccountActorCodeID {
		return true
	}

	if c == builtin5.AccountActorCodeID {
		return true
	}

	if c == builtin6.AccountActorCodeID {
		return true
	}

	if c == builtin7.AccountActorCodeID {
		return true
	}

	if c == builtin8.AccountActorCodeID {
		return true
	}

	return false
}

func IsLegacyVerifiedRegistryActor(c cid.Cid) bool {
	if c == builtin0.VerifiedRegistryActorCodeID {
		return true
	}

	if c == builtin2.VerifiedRegistryActorCodeID {
		return true
	}

	if c == builtin3.VerifiedRegistryActorCodeID {
		return true
	}

	if c == builtin4.VerifiedRegistryActorCodeID {
		return true
	}

	if c == builtin5.VerifiedRegistryActorCodeID {
		return true
	}

	if c == builtin6.VerifiedRegistryActorCodeID {
		return true
	}

	if c == builtin7.VerifiedRegistryActorCodeID {
		return true
	}

	if c == builtin8.VerifiedRegistryActorCodeID {
		return true
	}

	return false
}

func IsLegacyRewardActor(c cid.Cid) bool {
	if c == builtin0.RewardActorCodeID {
		return true
	}

	if c == builtin2.RewardActorCodeID {
		return true
	}

	if c == builtin3.RewardActorCodeID {
		return true
	}

	if c == builtin4.RewardActorCodeID {
		return true
	}

	if c == builtin5.RewardActorCodeID {
		return true
	}

	if c == builtin6.RewardActorCodeID {
		return true
	}

	if c == builtin7.RewardActorCodeID {
		return true
	}

	if c == builtin8.RewardActorCodeID {
		return true
	}

	return false
}

func IsLegacyPaymentChannelActor(c cid.Cid) bool {
	if c == builtin0.PaymentChannelActorCodeID {
		return true
	}

	if c == builtin2.PaymentChannelActorCodeID {
		return true
	}

	if c == builtin3.PaymentChannelActorCodeID {
		return true
	}

	if c == builtin4.PaymentChannelActorCodeID {
		return true
	}

	if c == builtin5.PaymentChannelActorCodeID {
		return true
	}

	if c == builtin6.PaymentChannelActorCodeID {
		return true
	}

	if c == builtin7.PaymentChannelActorCodeID {
		return true
	}

	if c == builtin8.PaymentChannelActorCodeID {
		return true
	}

	return false
}

func IsLegacyStorageMarketActor(c cid.Cid) bool {
	if c == builtin0.StorageMarketActorCodeID {
		return true
	}

	if c == builtin2.StorageMarketActorCodeID {
		return true
	}

	if c == builtin3.StorageMarketActorCodeID {
		return true
	}

	if c == builtin4.StorageMarketActorCodeID {
		return true
	}

	if c == builtin5.StorageMarketActorCodeID {
		return true
	}

	if c == builtin6.StorageMarketActorCodeID {
		return true
	}

	if c == builtin7.StorageMarketActorCodeID {
		return true
	}

	if c == builtin8.StorageMarketActorCodeID {
		return true
	}

	return false
}

func IsLegacyStorageMinerActor(c cid.Cid) bool {
	if c == builtin0.StorageMinerActorCodeID {
		return true
	}

	if c == builtin2.StorageMinerActorCodeID {
		return true
	}

	if c == builtin3.StorageMinerActorCodeID {
		return true
	}

	if c == builtin4.StorageMinerActorCodeID {
		return true
	}

	if c == builtin5.StorageMinerActorCodeID {
		return true
	}

	if c == builtin6.StorageMinerActorCodeID {
		return true
	}

	if c == builtin7.StorageMinerActorCodeID {
		return true
	}

	if c == builtin8.StorageMinerActorCodeID {
		return true
	}

	return false
}

func IsLegacyInitActor(c cid.Cid) bool {
	if c == builtin0.InitActorCodeID {
		return true
	}

	if c == builtin2.InitActorCodeID {
		return true
	}

	if c == builtin3.InitActorCodeID {
		return true
	}

	if c == builtin4.InitActorCodeID {
		return true
	}

	if c == builtin5.InitActorCodeID {
		return true
	}

	if c == builtin6.InitActorCodeID {
		return true
	}

	if c == builtin7.InitActorCodeID {
		return true
	}

	if c == builtin8.InitActorCodeID {
		return true
	}

	return false
}

func IsLegacySystemActor(c cid.Cid) bool {
	if c == builtin0.SystemActorCodeID {
		return true
	}

	if c == builtin2.SystemActorCodeID {
		return true
	}

	if c == builtin3.SystemActorCodeID {
		return true
	}

	if c == builtin4.SystemActorCodeID {
		return true
	}

	if c == builtin5.SystemActorCodeID {
		return true
	}

	if c == builtin6.SystemActorCodeID {
		return true
	}

	if c == builtin7.SystemActorCodeID {
		return true
	}

	if c == builtin8.SystemActorCodeID {
		return true
	}

	return false
}

func IsLegacyCronActor(c cid.Cid) bool {
	if c == builtin0.CronActorCodeID {
		return true
	}

	if c == builtin2.CronActorCodeID {
		return true
	}

	if c == builtin3.CronActorCodeID {
		return true
	}

	if c == builtin4.CronActorCodeID {
		return true
	}

	if c == builtin5.CronActorCodeID {
		return true
	}

	if c == builtin6.CronActorCodeID {
		return true
	}

	if c == builtin7.CronActorCodeID {
		return true
	}

	if c == builtin8.CronActorCodeID {
		return true
	}

	return false
}

func IsLegacyStoragePowerActor(c cid.Cid) bool {
	if c == builtin0.StoragePowerActorCodeID {
		return true
	}

	if c == builtin2.StoragePowerActorCodeID {
		return true
	}

	if c == builtin3.StoragePowerActorCodeID {
		return true
	}

	if c == builtin4.StoragePowerActorCodeID {
		return true
	}

	if c == builtin5.StoragePowerActorCodeID {
		return true
	}

	if c == builtin6.StoragePowerActorCodeID {
		return true
	}

	if c == builtin7.StoragePowerActorCodeID {
		return true
	}

	if c == builtin8.StoragePowerActorCodeID {
		return true
	}

	return false
}
