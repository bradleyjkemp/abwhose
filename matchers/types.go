package matchers

import (
	"strings"
)

type ProviderContact interface {
	Name() string // Returns a Name that uniquely identifies the recipient of an abuse report
}

type OnlineForm struct {
	ProviderName
	URL string
}

type AbuseEmail struct {
	ProviderName
	Email string
}

func (a AbuseEmail) Name() string {
	// Use a nice provider names if given
	if a.ProviderName != "" {
		return a.ProviderName.Name()
	}

	// Otherwise attempt to split out the domain from the email
	emailParts := strings.SplitN(a.Email, "@", 2)
	if len(emailParts) > 1 {
		return emailParts[1]
	}

	// Fall back to just the email itself
	return a.Email
}

type ProviderName string

func (m ProviderName) Name() string {
	return string(m)
}

type matcher struct {
	contact ProviderContact
	matches func(string) bool
}
