package dialer

import "context"

type exclusiveOutputMarkOwnerKey struct{}

// ContextWithExclusiveOutputMark declares socket mark ownership before the
// capture runtime starts. Dialers can then reject conflicting explicit marks
// during configuration checks, before any capture hooks are attached.
func ContextWithExclusiveOutputMark(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, exclusiveOutputMarkOwnerKey{}, owner)
}
