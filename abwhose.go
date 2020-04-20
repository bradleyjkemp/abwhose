package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"golang.org/x/net/publicsuffix"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: abwhose <phishing url>")
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var tabWriter = tabwriter.NewWriter(os.Stdout, 12, 2, 1, ' ', tabwriter.TabIndent)

func run(abuseURL string) error {
	var abusive *url.URL
	var err error
	if strings.Contains(abuseURL, "/") {
		// This looks like a full URL instead of a plain domain
		if !strings.HasPrefix(abuseURL, "http://") && !strings.HasPrefix(abuseURL, "https://") {
			// Doesn't have a protocol so won't url.Parse properly
			abuseURL = "http://" + abuseURL
		}

		abusive, err = url.Parse(abuseURL)
		if err != nil {
			return fmt.Errorf("couldn't parse URL: %w", err)
		}
	} else {
		// This is a plain domain name so we construct a URL directly
		abusive = &url.URL{
			Scheme: "http",
			Host:   abuseURL,
		}
	}

	if abusive.Hostname() == "" {
		return fmt.Errorf("%s doesn't look like a valid URL (hostname is empty)", abuseURL)
	}

	// First look up abuse details for the domain itself (this will be the registrar)
	rootDomain, _ := publicsuffix.EffectiveTLDPlusOne(abusive.Hostname())

	// First check if this is a shared host
	var sharedHost bool
	for _, matcher := range sharedHostMatchers {
		if match, display := matcher(rootDomain); match {
			if !sharedHost {
				fmt.Println("Report abuse to shared hosting provider:")
			}
			display()
			sharedHost = true
		}
	}
	// If this is a shared host then skip the WHOIS lookup
	// as that information isn't useful.
	if sharedHost {
		return nil
	}

	err = getAbuseReportDetails("Report abuse to domain registrar:", abusive, rootDomain)
	if err != nil {
		return fmt.Errorf("failed to get registrar abuse details: %w", err)
	}

	// Now look up the IP in order to find the hosting provider
	ips, err := net.LookupIP(abusive.Hostname())
	if err != nil {
		return fmt.Errorf("failed to find hosting provider: %w", err)
	}

	// Abuse details for the IP should be the hosting provider
	err = getAbuseReportDetails("Report abuse to host:", abusive, ips[0].String())
	if err != nil {
		return fmt.Errorf("failed to get host abuse details: %w", err)
	}
	return nil
}

func getAbuseReportDetails(header string, abusive *url.URL, query string) error {
	rawWhois, err := exec.Command("whois", query).CombinedOutput()
	if err != nil {
		return err
	}

	gotMatch := false
	for _, matcher := range whoisMatchers {
		if match, display := matcher(string(rawWhois)); match {
			if !gotMatch {
				fmt.Println(header)
				gotMatch = true
			}
			display()
		}
	}
	if gotMatch {
		return nil
	}

	// None of the specific matchers hit so use a generic one
	found, display := fallbackEmailMatcher(header, abusive, string(rawWhois))
	if found {
		display()
		return nil
	}

	fmt.Println(header)
	fmt.Println("  couldn't find any abuse contact details")
	return nil
}
