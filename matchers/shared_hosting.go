package matchers

import (
	"net/url"
	"strings"
)

// Returns the contact details of the shared hosting provider if it exists.
// If this matches, these contact details should be preferred over the
// registrar and hosting provider.
func IsSharedHostingProvider(u *url.URL) (bool, ProviderContact) {
	for _, m := range sharedHostMatchers {
		if m.matches(u.Host) {
			return true, m.contact
		}
	}
	return false, nil
}

// Matches content served by shared hosting providers i.e. where the abusive content
// is not served by the domain/server owner.
//
// Try to keep this sorted alphabetically by ProviderName
var sharedHostMatchers = []matcher{
	{OnlineForm{"000webhost", "https://www.000webhost.com/report-abuse"}, isSubDomainOf("000webhost.com")},
	{OnlineForm{"00webhost", "https://www.000webhost.com/report-abuse"}, isSubDomainOf("000webhostapp.com")},
	{OnlineForm{"Blogger", "https://support.google.com/blogger/answer/76315"}, isSubDomainOf("blogger.com")},
	{OnlineForm{"Blogger", "https://support.google.com/blogger/answer/76315"}, isSubDomainOf("blogspot.com")},
	{OnlineForm{"Google Cloud", "https://support.google.com/code/contact/cloud_platform_report"}, isSubDomainOf("appspot.com")},
	{OnlineForm{"Google Cloud", "https://support.google.com/code/contact/cloud_platform_report"}, isSubDomainOf("googleapis.com")},
	{OnlineForm{"Weebly", "https://www.weebly.com/uk/spam"}, isSubDomainOf("weebly.com")},
}

func isSubDomainOf(domain string) func(string) bool {
	return func(abusiveDomain string) bool {
		return abusiveDomain == domain || strings.HasSuffix(abusiveDomain, "."+domain)
	}
}
