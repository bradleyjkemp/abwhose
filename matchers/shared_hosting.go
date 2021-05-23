package matchers

import (
	"net/url"
	"strings"
)

// Returns the contact details of the shared hosting provider if it exists.
// If this matches, these contact details should be preferred over the
// registrar and hosting provider.
func IsSharedHostingProvider(u *url.URL) (bool, ProviderContact) {
	for _, m := range SharedHosts {
		if m.Matches(u.Host) {
			return true, m.Contact
		}
	}
	return false, nil
}

// Matches content served by shared hosting providers i.e. where the abusive content
// is not served by the domain/server owner.
//
// Try to keep this sorted alphabetically by ProviderName
var SharedHosts = []Matcher{
	{OnlineForm{"000webhost", "https://www.000webhost.com/report-abuse"}, isSubDomainOf("000webhost.com", "000webhostapp.com")},
	{AbuseEmail{"Adobe", "hellospark@adobe.com"}, isSubDomainOf("spark.adobe.com")},
	{OnlineForm{"Bitly", "https://bitly.is/reporting-abuse"}, isSubDomainOf("bit.ly")},
	{OnlineForm{"Blogger", "https://support.google.com/blogger/answer/76315"}, isSubDomainOf("blogger.com", "blogspot.com")},
	{OnlineForm{"Google Cloud", "https://support.google.com/code/contact/cloud_platform_report"}, isSubDomainOf("appspot.com", "googleapis.com", "web.app")},
	{AbuseEmail{"IBM", "abuse@softlayer.com"}, isSubDomainOf("appdomain.cloud")},
	{OnlineForm{"Notion", "https://www.notion.so/Report-inappropriate-content-9feb9f2f9d8c40b1b7d289b155907de0"}, isSubDomainOf("notion.so", "notion.com")},
	{OnlineForm{"Weebly", "https://www.weebly.com/uk/spam"}, isSubDomainOf("weebly.com")},
	{OnlineForm{"Yola", "https://helpcenter.yola.com/hc/en-us/requests/new?ticket_form_id=360001504300"}, isSubDomainOf("yolasite.com")},
}

func isSubDomainOf(domains ...string) func(string) bool {
	return func(abusiveDomain string) bool {
		for _, domain := range domains {
			if abusiveDomain == domain || strings.HasSuffix(abusiveDomain, "."+domain) {
				return true
			}
		}
		return false
	}
}
