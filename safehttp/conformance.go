package safehttp

// ConformanceCheck is a conformance check. It returns an error if the
// endpoint's interceptors are not configured in a desired way.
type ConformanceCheck func(pattern string, method string, interceptors []ConfiguredInterceptor) error
