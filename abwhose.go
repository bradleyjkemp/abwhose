package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"text/tabwriter"

	"golang.org/x/net/publicsuffix"
)

func main() {
	if err := run(os.Args[1]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var tabWriter = tabwriter.NewWriter(os.Stdout, 12, 2, 1, ' ', tabwriter.TabIndent)

func run(domain string) error {
	// First look up abuse details for the domain itself (this will be the registrar)
	tld, _ := publicsuffix.EffectiveTLDPlusOne(domain)

	// First check if this is a shared host
	var sharedHost bool
	for _, matcher := range sharedHostMatchers {
		if match, display := matcher(tld); match {
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

	err := getAbuseReportDetails("Report abuse to domain registrar:", domain, tld)
	if err != nil {
		return fmt.Errorf("failed to get registrar abuse details: %w", err)
	}

	// Now look up the IP in order to find the hosting provider
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("failed to find hosting provider: %w", err)
	}

	// Abuse details for the IP should be the hosting provider
	err = getAbuseReportDetails("Report abuse to host:", domain, ips[0].String())
	if err != nil {
		return fmt.Errorf("failed to get host abuse details: %w", err)
	}
	return nil
}

func getAbuseReportDetails(header, domain, query string) error {
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

	// None of the specific matchers hit so use a generic one
	if !gotMatch {
		found, display := fallbackEmailMatcher(header, domain, string(rawWhois))
		if found {
			display()
			return nil
		}
	}

	fmt.Println(header)
	fmt.Println("  couldn't find any abuse contact details")
	return nil
}
