package matchers

import (
	"fmt"
	"net"
	"net/url"
	"sort"

	"golang.org/x/net/publicsuffix"
)

// Gets the abuse contact details for the registrar of a domain name.
func Registrar(u *url.URL) ([]ProviderContact, error) {
	// First look up abuse details for the domain itself
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("failed to get root domain: %w", err)
	}

	return getContactsFromWHOIS(rootDomain)
}

// Gets the abuse contact details for the hosting provider of a domain name.
func HostingProvider(u *url.URL) ([]ProviderContact, error) {
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("failed to find hosting provider: %w", err)
	}

	contacts := map[string]ProviderContact{}
	for _, ip := range ips {
		ipContacts, err := getContactsFromWHOIS(ip.String())
		if err != nil {
			return nil, err
		}

		for _, contact := range ipContacts {
			contacts[contact.Name()] = contact
		}
	}

	dedupedContacts := make([]ProviderContact, 0, len(contacts))
	for _, contact := range contacts {
		dedupedContacts = append(dedupedContacts, contact)
	}
	sort.Slice(dedupedContacts, func(i, j int) bool {
		return dedupedContacts[i].Name() < dedupedContacts[j].Name()
	})
	return dedupedContacts, nil
}
