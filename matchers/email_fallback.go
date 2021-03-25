package matchers

import (
	"regexp"
	"sort"
	"strings"
)

var emailRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(abuse@[a-z0-9\-.]*)`),
	regexp.MustCompile(`(?m)^OrgAbuseEmail:\s+(.*)$`),
	regexp.MustCompile(`(?m)^Registrar Abuse Contact Email:\s+(.+)$`),
}

func getRawEmailContacts(rawWhois string) []ProviderContact {
	var emails = map[string]struct{}{}
	for _, matcher := range emailRegexes {
		for _, email := range matcher.FindAllStringSubmatch(rawWhois, -1) {
			emails[strings.TrimSpace(email[1])] = struct{}{}
		}
	}
	if len(emails) == 0 {
		return nil
	}

	sortedEmails := make([]ProviderContact, 0, len(emails))
	for email := range emails {
		sortedEmails = append(sortedEmails, AbuseEmail{ProviderName(email), email})
	}
	sort.Slice(sortedEmails, func(i, j int) bool {
		return sortedEmails[i].(AbuseEmail).Email < sortedEmails[j].(AbuseEmail).Email
	})
	return sortedEmails
}
