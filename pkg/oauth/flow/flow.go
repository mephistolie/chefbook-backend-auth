package flow

import (
	"context"
	"time"
)

const TTL = 10 * time.Minute

type bindingKey struct{}

func WithBinding(ctx context.Context, binding string) context.Context {
	return context.WithValue(ctx, bindingKey{}, binding)
}
func Binding(ctx context.Context) string { value, _ := ctx.Value(bindingKey{}).(string); return value }

type Store interface {
	CreateOAuthState(context.Context, string, string, string) (string, error)
	ConsumeOAuthState(context.Context, string, string, string, string) error
}
