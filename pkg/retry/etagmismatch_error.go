package retry

import (
	"net/http"
	"regexp"
)

const (
	// TODO(mainred): etag mismatch error message is not consistent across Azure APIs, we need to normalize it or add more error messages.
	// Example error message for CRP
	// Etag provided in if-match header {0} does not match etag {1} of resource.
	//   where {0} and {1} are the etags provided in the request and the resource respectively.
	EtagMismatchPattern = `Etag provided in if-match header ([^\s]+) does not match etag ([^\s]+) of resource`
)

type EtagMismatchError struct {
	currentEtag string
	latestEtag  string
}

func NewEtagMismatchError(httpStatusCode int, respBody string) *EtagMismatchError {
	if httpStatusCode != http.StatusPreconditionFailed {
		return nil
	}

	currentEtag, latestEtag, match := getMatchedLatestAndCurrentEtags(respBody)
	if !match {
		return nil
	}

	return &EtagMismatchError{
		currentEtag: currentEtag,
		latestEtag:  latestEtag,
	}
}

func (e *EtagMismatchError) Error() string {
	return ""
}

func (e *EtagMismatchError) CurrentEtag() string {
	return e.currentEtag
}

func (e *EtagMismatchError) LatestEtag() string {
	return e.latestEtag
}

// isPreconditionFailedEtagMismatch returns true the if the request failed for Etag mismatch
func IsPreconditionFailedEtagMismatch(httpStatusCode int, respBody string) bool {

	if httpStatusCode != http.StatusPreconditionFailed {
		return false
	}

	_, _, match := getMatchedLatestAndCurrentEtags(respBody)
	return match

}

func getMatchedLatestAndCurrentEtags(respBody string) (currentEtag string, latestEtag string, match bool) {

	re := regexp.MustCompile(EtagMismatchPattern)
	matches := re.FindStringSubmatch(respBody)
	if len(matches) != 3 {
		return
	}

	currentEtag = matches[1]
	latestEtag = matches[2]
	match = true

	return
}
