package conformance

import (
	"errors"

	"github.com/google/go-safeweb/safehttp/plugins/hsts"
	"github.com/google/go-safeweb/safehttp/plugins/staticheaders"
	"github.com/google/go-safeweb/safehttp/plugins/xsrf"

	"github.com/google/go-safeweb/safehttp"
)

// StrictChecks returns a list of conformance checks for strict security.
func StrictChecks() []safehttp.ConformanceCheck {
	return []safehttp.ConformanceCheck{
		SingleInterceptorCheck(hsts.InterceptorCheck).Check,
		staticheaders.ConformanceCheck,
		xsrf.ConformanceCheck,
	}
}

// SingleInterceptorCheck is a conformance check. The function should return
// (true, _) if a supported interceptor was found, an the error return value
// should indicate whether the check should pass. The SingleInterceptorCheck
// conformance check will pass if there is exactly one supported interceptor
// found and the check returns no errors.
type SingleInterceptorCheck func(pattern string, method string, ip safehttp.ConfiguredInterceptor) (found bool, err error)

// Check checks whether there is exactly one interceptor that matches, and the
// check for this interceptor returns no errors.
func (s SingleInterceptorCheck) Check(pattern string, method string, interceps []safehttp.ConfiguredInterceptor) error {
	present := false
	for _, ci := range interceps {
		if found, err := s(pattern, method, ci); found {
			if present {
				return errors.New("multiple interceptors found")
			}
			present = true

			if err != nil {
				return err
			}
		}
	}
	return nil
}
