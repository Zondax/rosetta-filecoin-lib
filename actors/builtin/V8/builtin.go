package V8

import (
	"github.com/ipfs/go-cid"
	"github.com/zondax/rosetta-filecoin-lib/actors"
)

const (
	// BuiltinActorsKeys NetworkVersion: 16, ActorsVersion: 8
	// from lotus cli cmd: 'lotus state actor-cids'
	ActorAccountCode          = "bafk2bzacebs3prrp2swegbefkh3hsyuqwvxrnluoiwpmkxzhfh6y4wecdxwv4"
	ActorCronCode             = "bafk2bzacedifvgycuibukwnaesekwdxiqpdt5m25ga7vkh5mgrngskbxtputu"
	ActorInitCode             = "bafk2bzaceaejm2x4jwqownf5jyxjbga4pwim7d7lw6yfxdvgyuetybrwzc7tu"
	ActorStorageMarketCode    = "bafk2bzaceafh7p4wdafrplys6ejimgf66apaaz4f4iuu3rsk3beqfnzzbrras"
	ActorStorageMinerCode     = "bafk2bzaceaq7g4zded65xa5oxwlwx75brh5gxcjthtdu5zl3ei5vtvbnfavzy"
	ActorMultisigCode         = "bafk2bzaceczfz65fvn662qrkdgtmokve7oj3wmdgkbhvucwaigyihues3u6ke"
	ActorPaymentChannelCode   = "bafk2bzaceaguosntcgqhbd5cknw6xe5fa6qxjxarft6osxmuh6ju2y4zrxmsi"
	ActorStoragePowerCode     = "bafk2bzacean7gm2tjoq4hsvsimdx2clvfue6yfls2hcee6sxvm4ld7l4e42jk"
	ActorRewardCode           = "bafk2bzacednljsae765kb6dsgfcg4jebfjza5mnqbauemzpxiizguuyi4i3yi"
	ActorSystemCode           = "bafk2bzacecr3qaggetreqfeurdjek7kjzfeuapiuprwp26hixmjtdvbgb3yfk"
	ActorVerifiedRegistryCode = "bafk2bzaceceekx5csbzck4lq5rlqexq2tu3njbixyglw452hc554aabpxiaai"
)

var (
	AccountActorCodeID, _          = cid.Parse(ActorAccountCode)
	CronActorCodeID, _             = cid.Parse(ActorCronCode)
	InitActorCodeID, _             = cid.Parse(ActorInitCode)
	StorageMarketActorCodeID, _    = cid.Parse(ActorStorageMarketCode)
	StorageMinerActorCodeID, _     = cid.Parse(ActorStorageMinerCode)
	MultisigActorCodeID, _         = cid.Parse(ActorMultisigCode)
	PaymentChannelActorCodeID, _   = cid.Parse(ActorPaymentChannelCode)
	StoragePowerActorCodeID, _     = cid.Parse(ActorStoragePowerCode)
	RewardActorCodeID, _           = cid.Parse(ActorRewardCode)
	SystemActorCodeID, _           = cid.Parse(ActorSystemCode)
	VerifiedRegistryActorCodeID, _ = cid.Parse(ActorVerifiedRegistryCode)
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
	return BuiltinActorsKeys[actorCode.String()] == actors.ActorMultisigName
}

func GetActorNameFromCid(actorCode cid.Cid) (bool, string) {
	actorName, ok := BuiltinActorsKeys[actorCode.String()]
	if ok {
		return true, actorName
	}

	return false, actors.UnknownStr
}
