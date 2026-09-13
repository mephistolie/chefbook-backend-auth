package logging

import (
	"context"

	"github.com/mephistolie/chefbook-backend-common/log"
)

type Events struct{}

var Default Events

type PostgresOperationData struct {
	Operation string
	UserID    string
	MessageID string
	Entity    string
	Count     int
}

type MailData struct {
	Kind           string
	UserID         string
	WithSharedData *bool
}

type OAuthData struct {
	Provider string
	UserID   string
}

type MessageData struct {
	MessageID string
	Type      string
	Exchange  string
}

func (Events) PostgresOperationFailed(ctx context.Context, data PostgresOperationData, err error) {
	log.LogError(ctx, log.Event{
		Event:     "auth.postgres.operation.failed",
		Message:   "postgres operation failed",
		Component: log.ComponentPostgres,
		UserID:    data.UserID,
		MessageID: data.MessageID,
		Operation: data.Operation,
		ErrorType: safeErrorType(err, "postgres_error"),
		Payload:   postgresPayload(data),
	}, nil)
}

func (Events) PostgresOperationWarned(ctx context.Context, data PostgresOperationData, err error) {
	log.LogWarn(ctx, log.Event{
		Event:     "auth.postgres.operation.warned",
		Message:   "postgres operation completed with a warning",
		Component: log.ComponentPostgres,
		UserID:    data.UserID,
		MessageID: data.MessageID,
		Operation: data.Operation,
		ErrorType: safeErrorType(err, "postgres_error"),
		Payload:   postgresPayload(data),
	})
}

func (Events) PostgresRowScanFailed(ctx context.Context, data PostgresOperationData, err error) {
	log.LogError(ctx, log.Event{
		Event:     "auth.postgres.row.scan_failed",
		Message:   "unable to scan postgres row",
		Component: log.ComponentPostgres,
		UserID:    data.UserID,
		Operation: data.Operation,
		ErrorType: safeErrorType(err, "postgres_scan_error"),
		Payload:   postgresPayload(data),
	}, nil)
}

func (Events) PostgresLookupMissed(ctx context.Context, data PostgresOperationData) {
	log.Log(ctx, log.Event{
		Event:     "auth.postgres.lookup.missed",
		Message:   "postgres lookup returned no matching record",
		Component: log.ComponentPostgres,
		UserID:    data.UserID,
		Operation: data.Operation,
		Payload:   postgresPayload(data),
	})
}

func (Events) PostgresLookupWarned(ctx context.Context, data PostgresOperationData) {
	log.LogWarn(ctx, log.Event{
		Event:     "auth.postgres.lookup.warned",
		Message:   "postgres lookup returned no matching record",
		Component: log.ComponentPostgres,
		UserID:    data.UserID,
		Operation: data.Operation,
		Payload:   postgresPayload(data),
	})
}

func (Events) UserCreationStarted(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:     "auth.user.creation.started",
		Message:   "user creation started",
		Component: log.ComponentPostgres,
		UserID:    userID,
	})
}

func (Events) PasswordResetReused(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:     "auth.password_reset.reused",
		Message:   "existing password reset request reused",
		Component: log.ComponentPostgres,
		UserID:    userID,
	})
}

func (Events) ActivationCodeRejected(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:     "auth.activation_code.rejected",
		Message:   "profile activation code rejected",
		Component: log.ComponentPostgres,
		UserID:    userID,
	})
}

func (Events) PasswordResetCodeRejected(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:     "auth.password_reset.code_rejected",
		Message:   "password reset code rejected",
		Component: log.ComponentPostgres,
		UserID:    userID,
	})
}

func (Events) OAuthIdentityOccupied(ctx context.Context, data OAuthData) {
	log.LogWarn(ctx, log.Event{
		Event:     "auth.oauth.identity_occupied",
		Message:   "oauth identity is already connected",
		Component: log.ComponentPostgres,
		UserID:    data.UserID,
		Payload: map[string]any{
			"provider": data.Provider,
		},
	})
}

func (Events) PasswordInvalid(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:   "auth.credentials.password_invalid",
		Message: "password validation failed",
		UserID:  userID,
	})
}

func (Events) PasswordHashFailed(ctx context.Context, err error) {
	log.LogError(ctx, log.Event{
		Event:   "auth.credentials.password_hash_failed",
		Message: "unable to hash password",
	}, err)
}

func (Events) ProfileNotActivated(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:   "auth.profile.not_activated",
		Message: "profile is not activated",
		UserID:  userID,
	})
}

func (Events) ProfileBlocked(ctx context.Context, userID string) {
	log.LogWarn(ctx, log.Event{
		Event:   "auth.profile.blocked",
		Message: "profile is blocked",
		UserID:  userID,
	})
}

func (Events) ProfileAlreadyExists(ctx context.Context, userID string) {
	log.LogWarn(ctx, log.Event{
		Event:   "auth.profile.already_exists",
		Message: "activated profile already exists",
		UserID:  userID,
	})
}

func (Events) SessionCreationStarted(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:   "auth.session.creation.started",
		Message: "session creation started",
		UserID:  userID,
	})
}

func (Events) AccessTokenCreationFailed(ctx context.Context, userID string, err error) {
	log.LogError(ctx, log.Event{
		Event:   "auth.access_token.creation_failed",
		Message: "unable to create access token",
		UserID:  userID,
	}, err)
}

func (Events) OAuthCodeRejected(ctx context.Context, data OAuthData, err error) {
	log.LogWarn(ctx, log.Event{
		Event:     "auth.oauth.code_rejected",
		Message:   "oauth authorization code rejected",
		UserID:    data.UserID,
		ErrorType: safeErrorType(err, "oauth_provider_error"),
		Payload: map[string]any{
			"provider": data.Provider,
		},
	})
}

func (Events) FirebaseImportStarted(ctx context.Context) {
	log.Log(ctx, log.Event{
		Event:     "auth.firebase.import.started",
		Message:   "firebase profile import started",
		Component: log.ComponentFirebase,
	})
}

func (Events) FirebaseIdentityOccupied(ctx context.Context) {
	log.LogWarn(ctx, log.Event{
		Event:     "auth.firebase.identity_occupied",
		Message:   "firebase identity is already connected",
		Component: log.ComponentFirebase,
	})
}

func (Events) FirebaseProfileFetchFailed(ctx context.Context, err error) {
	log.LogError(ctx, log.Event{
		Event:     "auth.firebase.profile_fetch_failed",
		Message:   "unable to fetch firebase profile",
		Component: log.ComponentFirebase,
		ErrorType: safeErrorType(err, "firebase_api_error"),
	}, nil)
}

func (Events) FirebaseProfileConnected(ctx context.Context, userID string) {
	log.Log(ctx, log.Event{
		Event:     "auth.firebase.profile_connected",
		Message:   "firebase profile connected",
		Component: log.ComponentFirebase,
		UserID:    userID,
	})
}

func (Events) FirebaseProfileConnectFailed(ctx context.Context, userID string, err error) {
	log.LogError(ctx, log.Event{
		Event:     "auth.firebase.profile_connect_failed",
		Message:   "unable to connect firebase profile",
		Component: log.ComponentFirebase,
		UserID:    userID,
	}, err)
}

func (Events) FirebaseClientInitialized(ctx context.Context) {
	log.Log(ctx, log.Event{
		Event:     "auth.firebase.client_initialized",
		Message:   "firebase client initialized",
		Component: log.ComponentFirebase,
	})
}

func (Events) ProfileDeletionTargetMissing(ctx context.Context, userID string) {
	log.LogWarn(ctx, log.Event{
		Event:   "auth.profile_deletion.target_missing",
		Message: "profile scheduled for deletion was not found",
		UserID:  userID,
	})
}

func (Events) MailDeliveryStarted(ctx context.Context, data MailData) {
	log.Log(ctx, log.Event{
		Event:   "auth.mail.delivery.started",
		Message: "mail delivery started",
		UserID:  data.UserID,
		Payload: mailPayload(data),
	})
}

func (Events) MailTemplateRenderFailed(ctx context.Context, data MailData, err error) {
	log.LogError(ctx, log.Event{
		Event:   "auth.mail.template_render_failed",
		Message: "unable to render mail template",
		UserID:  data.UserID,
		Payload: mailPayload(data),
	}, err)
}

func (Events) MailDeliveryFailed(ctx context.Context, data MailData, err error) {
	log.LogError(ctx, log.Event{
		Event:   "auth.mail.delivery_failed",
		Message: "unable to deliver mail",
		UserID:  data.UserID,
		Payload: mailPayload(data),
	}, err)
}

func (Events) MessagePublishStarted(ctx context.Context, data MessageData) {
	log.Log(ctx, log.Event{
		Event:     "auth.mq.message.publish_started",
		Message:   "message publish started",
		Component: log.ComponentAMQP,
		MessageID: data.MessageID,
		Payload: map[string]any{
			"message_type": data.Type,
			"exchange":     data.Exchange,
		},
	})
}

func (Events) MessagePublished(ctx context.Context, data MessageData) {
	log.Log(ctx, log.Event{
		Event:     "auth.mq.message.published",
		Message:   "message published",
		Component: log.ComponentAMQP,
		MessageID: data.MessageID,
		Payload: map[string]any{
			"message_type": data.Type,
			"exchange":     data.Exchange,
		},
	})
}

func (Events) MessagePublishFailed(ctx context.Context, data MessageData, err error) {
	log.LogWarnError(ctx, log.Event{
		Event:     "auth.mq.message.publish_failed",
		Message:   "unable to publish message",
		Component: log.ComponentAMQP,
		MessageID: data.MessageID,
		Payload: map[string]any{
			"message_type": data.Type,
			"exchange":     data.Exchange,
		},
	}, err)
}

func (Events) UsernameValidatorInitializationFailed(ctx context.Context, err error) {
	log.LogError(ctx, log.Event{
		Event:   "auth.username.validator_initialization_failed",
		Message: "unable to initialize username validator",
	}, err)
}

func postgresPayload(data PostgresOperationData) map[string]any {
	payload := make(map[string]any, 2)
	if data.Entity != "" {
		payload["entity"] = data.Entity
	}
	if data.Count > 0 {
		payload["count"] = data.Count
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func mailPayload(data MailData) map[string]any {
	payload := map[string]any{"kind": data.Kind}
	if data.WithSharedData != nil {
		payload["with_shared_data"] = *data.WithSharedData
	}
	return payload
}
