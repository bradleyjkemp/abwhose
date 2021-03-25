package matchers

type ProviderContact interface {
	Name() string // Returns a Name that uniquely identifies the recipient of an abuse report
}

type OnlineForm struct {
	ProviderName
	URL string
}

type AbuseEmail struct {
	ProviderName
	Email string
}

type ProviderName string

func (m ProviderName) Name() string {
	return string(m)
}

type matcher struct {
	contact ProviderContact
	matches func(string) bool
}
