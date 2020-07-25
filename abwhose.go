package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/bradleyjkemp/abwhose/matchers"
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

func run(query string) error {
	u, err := parseURL(query)
	if err != nil {
		return err
	}

	if ok, contact := matchers.IsSharedHostingProvider(u); ok {
		fmt.Println("Report abuse to shared hosting provider:")
		printContactDetails(u, contact)
		// If this is a shared host then skip the rest of the lookups
		// as that information isn't useful.
		return nil
	}

	contacts, err := matchers.Registrar(u)
	if err != nil {
		return err
	}
	fmt.Println("Report abuse to domain registrar:")
	printContactDetails(u, contacts...)

	contacts, err = matchers.HostingProvider(u)
	if err != nil {
		return err
	}
	fmt.Println("Report abuse to hosting provider:")
	printContactDetails(u, contacts...)
	return nil
}

func parseURL(input string) (*url.URL, error) {
	if !strings.Contains(input, "/") {
		// This is likely a plain domain name so we construct a URL directly
		return &url.URL{
			Scheme: "http",
			Host:   input,
		}, nil
	}

	// This looks like a full URL instead of a plain domain
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		// Doesn't have a protocol so won't url.Parse properly
		input = "http://" + input
	}

	u, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse URL: %w", err)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%s doesn't look like a valid URL (hostname is empty)", input)
	}

	return u, nil
}

var tabWriter = tabwriter.NewWriter(os.Stdout, 12, 2, 1, ' ', tabwriter.TabIndent)

func printContactDetails(u *url.URL, contacts ...matchers.ProviderContact) {
	for _, contact := range contacts {
		switch c := contact.(type) {
		case matchers.AbuseEmail:
			if emailTemplateConfigured() {
				offerToSendEmail(u, c)
			} else {
				fmt.Fprintf(tabWriter, "  Email:\t%s\n", c.Email)
			}

		case matchers.OnlineForm:
			fmt.Fprintf(tabWriter, "  %s:\tFill out abuse form %s\n", contact.Name(), c.URL)

		default:
			panic(fmt.Sprintf("unknown contact type: %T", contact))
		}
	}
	if len(contacts) == 0 {
		fmt.Fprintf(tabWriter, "  Couldn't find any contact details\n")
	}
	tabWriter.Flush()
}
