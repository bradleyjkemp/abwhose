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
	registrarAbuse, err := getAbuseReportDetails(tld)
	if err != nil {
		return fmt.Errorf("failed to get registrar abuse details: %w", err)
	}

	fmt.Println("Report abuse to domain registrar:")
	for name, details := range registrarAbuse {
		fmt.Fprintf(tabWriter, "  %s:\t%s\n", name, details)
	}
	tabWriter.Flush()

	// Now look up the IP in order to find the hosting provider
	ips, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %w", err)
	}

	// Abuse details for the IP should be the hosting provider
	hostAbuse, err := getAbuseReportDetails(ips[0].String())
	if err != nil {
		return fmt.Errorf("failed to get host abuse details: %w", err)
	}

	fmt.Println("Report abuse to host:")
	for name, details := range hostAbuse {
		fmt.Fprintf(tabWriter, "  %s:\t%s\n", name, details)
	}
	tabWriter.Flush()
	return nil
}

func getAbuseReportDetails(query string) (map[string]string, error) {
	rawWhois, err := exec.Command("whois", query).CombinedOutput()
	if err != nil {
		return nil, err
	}

	contactDetails := map[string]string{}
	for name, matcher := range matchers {
		if match, message := matcher(string(rawWhois)); match {
			contactDetails[name] = message
		}
	}

	// None of the specific matchers hit so use a generic one
	if len(contactDetails) == 0 {
		found, emails := fallbackEmailMatcher(string(rawWhois))
		if found {
			contactDetails["Email"] = emails
		}
	}

	// Still found nothing so just set an error message
	if len(contactDetails) == 0 {
		contactDetails["Error"] = "Couldn't find any contact details."
	}

	return contactDetails, nil
}
