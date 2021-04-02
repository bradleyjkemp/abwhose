package matchers

import "os/exec"

var WHOISClient = func(query string) (rawResult []byte, err error) {
	return exec.Command("whois", query).CombinedOutput()
}
