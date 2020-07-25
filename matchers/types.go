package matchers

type ProviderContact interface {
	Name() string // Returns a Name that uniquely identifies the recipient of an abuse report
}

type OnlineForm struct {
	providerID
	URL string
}

type AbuseEmail struct {
	providerID
	Email string
}

type providerID string

func (m providerID) Name() string {
	return string(m)
}

type matcher struct {
	contact ProviderContact
	matches func(string) bool
}
