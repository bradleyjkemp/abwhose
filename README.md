# abwhose [![GitHub release](https://img.shields.io/github/release/bradleyjkemp/abwhose.svg)](https://github.com/bradleyjkemp/abwhose/releases/latest)

The simplest way to find the *correct* place to report a domain for abuse.

```bash
$ abwhose phishing-mcphishface.com

Report abuse to domain registrar:
  Email:     abuse@theregistrar.com
Report abuse to host:
  HostPhish: Submit this form - https://wehostphish.biz/dev/null.php
```

Never again send an abuse report via email only to get a response days later saying:
> Sorry, we only take abuse reports through this online form: https://reallyslow.com/new-report

Instead use `abwhose` and always send your abuse reports to the correct place the first time.

### Installation

```bash
brew install bradleyjkemp/formulae/abwhose
```

### Pre-filling abuse email reports

`abwhose` can automatically open your email client pre-filled with a template of your choice.

To use this feature just:
1. Create an email template file somewhere on your filesystem (see below for an example).
1. Set the environment variable `ABWHOSE_MAILTO_TEMPLATE` to the path to you template file.

An example template you could use is:
```
mailto:{{.recipient}}?subject=Phishing site: {{.domain}}&body=To whom it may concern,

Please take down this phishing site: {{.domain}}

Thanks
```
