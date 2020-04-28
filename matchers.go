package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

type matcher func(string) (match bool, display func())

var sharedHostMatchers = []matcher{
	domainMatcher("000webhost.com", onlineFormMessage("000webhost", "https://www.000webhost.com/report-abuse")),
	domainMatcher("000webhostapp.com", onlineFormMessage("00webhost", "https://www.000webhost.com/report-abuse")),
	domainMatcher("blogger.com", onlineFormMessage("Blogger", "https://support.google.com/blogger/answer/76315")),
	domainMatcher("blogspot.com", onlineFormMessage("Blogger", "https://support.google.com/blogger/answer/76315")),
	domainMatcher("weebly.com", onlineFormMessage("Weebly", "https://www.weebly.com/uk/spam")),
	domainMatcher("appspot.com", onlineFormMessage("Google Cloud", "https://support.google.com/code/contact/cloud_platform_report")),
	domainMatcher("googleapis.com", onlineFormMessage("Google Cloud", "https://support.google.com/code/contact/cloud_platform_report")),
}

var whoisMatchers = []matcher{
	containsMatcher("abuse@cloudflare.com", onlineFormMessage("Cloudflare", "https://www.cloudflare.com/abuse/form")),
	containsMatcher("abuse@godaddy.com", onlineFormMessage("GoDaddy", "https://supportcenter.godaddy.com/AbuseReport")),
	containsMatcher("abuse@namecheap.com", onlineFormMessage("Namecheap", "https://support.namecheap.com/index.php?/Tickets/Submit")),
	containsMatcher("abuse@namesilo.com", onlineFormMessage("Namesilo", "https://www.namesilo.com/report_abuse.php or https://new.namesilo.com/phishing_report.php")),
	containsMatcher("abuse-contact@publicdomainregistry.com", onlineFormMessage("PublicDomainRegistry", "http://publicdomainregistry.com/report-abuse-complain/")),
	containsMatcher("abuse@tucows.com", onlineFormMessage("Tucows", "https://tucowsdomains.com/report-abuse/")),
	containsMatcher("domainabuse@tucows.com", onlineFormMessage("Tucows", "https://tucowsdomains.com/report-abuse/")),
}

var emailMatchers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(abuse@[a-z0-9\-.]*)`),
	regexp.MustCompile(`(?m)^OrgAbuseEmail:\s+(.*)$`),
	regexp.MustCompile(`(?m)^Registrar Abuse Contact Email:\s+(.+)$`),
}

func fallbackEmailMatcher(header string, abusive *url.URL, whois string) (bool, func()) {
	var emails = map[string]struct{}{}
	for _, matcher := range emailMatchers {
		for _, email := range matcher.FindAllStringSubmatch(whois, -1) {
			emails[strings.TrimSpace(email[1])] = struct{}{}
		}
	}
	if len(emails) == 0 {
		return false, nil
	}

	sortedEmails := make([]string, 0, len(emails))
	for email := range emails {
		sortedEmails = append(sortedEmails, email)
	}
	sort.Slice(sortedEmails, func(i, j int) bool {
		return sortedEmails[i] < sortedEmails[j]
	})

	return true, func() {
		emailTemplateFile, found := os.LookupEnv("ABWHOSE_MAILTO_TEMPLATE")
		if !found {
			fmt.Println(header)
			fmt.Fprintf(tabWriter, "  Email:\t%s\n", sortedEmails)
			tabWriter.Flush()
			return
		}

		emailTemplateContents, err := ioutil.ReadFile(emailTemplateFile)
		if err != nil {
			fmt.Printf("Failed reading email template: %v\n", err)
			return
		}
		mailto := &bytes.Buffer{}
		err = template.Must(template.New("email").Parse(string(emailTemplateContents))).Execute(mailto, map[string]interface{}{
			"domain":    strings.Replace(abusive.Hostname(), ".", "[.]", -1),
			"url":       strings.Replace(abusive.Hostname(), ".", "[.]", -1) + abusive.RawPath + abusive.RawQuery,
			"recipient": strings.Join(sortedEmails, ";"),
		})
		if err != nil {
			fmt.Printf("Error templating email: %v\n", err)
			return
		}
		fmt.Println(header)
		fmt.Printf("  Send email to %s? [Y/n] ", sortedEmails)
		if userSaysYes() {
			exec.Command("open", mailto.String()).Run()
		}
	}
}

func userSaysYes() bool {
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil && err.Error() != "unexpected newline" {
		panic(err)
	}
	okayResponses := map[string]bool{
		"":    true,
		"y":   true,
		"yes": true,
	}
	if okayResponses[strings.ToLower(response)] {
		return true
	}
	return false
}

func containsMatcher(contents string, display func()) matcher {
	return func(whois string) (bool, func()) {
		if strings.Contains(whois, contents) {
			return true, display
		}

		return false, nil
	}
}

func domainMatcher(domain string, display func()) matcher {
	return func(abusiveDomain string) (bool, func()) {
		if abusiveDomain == domain || strings.HasSuffix(abusiveDomain, "."+domain) {
			return true, display
		}

		return false, nil
	}
}

func onlineFormMessage(name, url string) func() {
	return func() {
		fmt.Fprintf(tabWriter, "  %s:\tFill out abuse form %s\n", name, url)
		tabWriter.Flush()
	}
}
