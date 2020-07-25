package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/bradleyjkemp/abwhose/matchers"
)

func emailTemplateConfigured() bool {
	_, configured := os.LookupEnv("ABWHOSE_MAILTO_TEMPLATE")
	return configured
}

func offerToSendEmail(u *url.URL, contact matchers.AbuseEmail) {
	emailTemplateFile, _ := os.LookupEnv("ABWHOSE_MAILTO_TEMPLATE")
	emailTemplateContents, err := ioutil.ReadFile(emailTemplateFile)
	if err != nil {
		fmt.Printf("Failed reading email template: %v\n", err)
		return
	}
	mailto := &bytes.Buffer{}
	err = template.Must(template.New("email").Parse(string(emailTemplateContents))).Execute(mailto, map[string]interface{}{
		"domain":    strings.Replace(u.Hostname(), ".", "[.]", -1),
		"url":       strings.Replace(u.Hostname(), ".", "[.]", -1) + u.RawPath + u.RawQuery,
		"recipient": contact.Email,
	})
	if err != nil {
		fmt.Printf("Error templating email: %v\n", err)
		return
	}
	fmt.Printf("  Send email to %s? [Y/n] ", contact.Email)
	if userSaysYes() {
		exec.Command("open", mailto.String()).Run()
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
