package mq

const ExchangeProfiles = "auth.profiles"
const AppId = "auth-service"

const MsgTypeProfileCreated = "profile.created"
const MsgTypeProfileFirebaseImport = "profile.firebase.import"
const MsgTypeProfileDeleted = "profile.deleted"

type MsgBodyProfileCreated struct {
	UserId string `json:"userId"`
}

type MsgBodyProfileFirebaseImport struct {
	UserId     string `json:"userId"`
	FirebaseId string `json:"firebaseId"`
}

type MsgBodyProfileDeleted struct {
	UserId string `json:"userId"`
}
