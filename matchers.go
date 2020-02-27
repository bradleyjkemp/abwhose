package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type matcher func(string) (match bool, message string)

var sharedHostMatchers = map[string]matcher{
	"000webhost":    domainMatcher("000webhost.com", onlineFormMessage("https://www.000webhost.com/report-abuse")),
	"000webhostapp": domainMatcher("000webhostapp.com", onlineFormMessage("https://www.000webhost.com/report-abuse")),
	"Blogger":       domainMatcher("blogger.com", onlineFormMessage("https://support.google.com/blogger/answer/76315")),
	"Blogspot":      domainMatcher("blogspot.com", onlineFormMessage("https://support.google.com/blogger/answer/76315")),
	"Weebly":        domainMatcher("weebly.com", onlineFormMessage("https://www.weebly.com/uk/spam")),
}

var whoisMatchers = map[string]matcher{
	"Cloudflare": containsMatcher("abuse@cloudflare.com", onlineFormMessage("https://www.cloudflare.com/abuse/form")),
	"GoDaddy":    containsMatcher("abuse@godaddy.com", onlineFormMessage("https://supportcenter.godaddy.com/AbuseReport")),
	"Namecheap":  containsMatcher("abuse@namecheap.com", onlineFormMessage("https://support.namecheap.com/index.php?/Tickets/Submit")),
	"Namesilo":   containsMatcher("abuse@namesilo.com", onlineFormMessage("https://www.namesilo.com/report_abuse.php or https://new.namesilo.com/phishing_report.php")),
}

var emailMatchers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(abuse@[a-z0-9\-.]*)`),
	regexp.MustCompile(`OrgAbuseEmail:\s+(.*)$`),
}

func fallbackEmailMatcher(whois string) (bool, string) {
	var emails = map[string]struct{}{}
	for _, matcher := range emailMatchers {
		for _, email := range matcher.FindAllStringSubmatch(whois, -1) {
			emails[email[0]] = struct{}{}
		}
	}

	if len(emails) == 0 {
		return false, ""
	}

	sortedEmails := make([]string, 0, len(emails))
	for email := range emails {
		sortedEmails = append(sortedEmails, email)
	}
	sort.Slice(sortedEmails, func(i, j int) bool {
		return sortedEmails[i] < sortedEmails[j]
	})
	return true, strings.Join(sortedEmails, ", ")
}

func containsMatcher(contents, message string) matcher {
	return func(whois string) (bool, string) {
		if strings.Contains(whois, contents) {
			return true, message
		}

		return false, ""
	}
}

func domainMatcher(domain, message string) matcher {
	return func(abusiveDomain string) (bool, string) {
		if abusiveDomain == domain || strings.HasSuffix(abusiveDomain, "."+domain) {
			return true, message
		}

		return false, ""
	}
}

func onlineFormMessage(url string) string {
	return fmt.Sprintf("Fill out abuse form %s", url)
}
