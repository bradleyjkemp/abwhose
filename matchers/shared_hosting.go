package matchers

import (
	"net/url"
	"strings"
)

// Returns the contact details of the shared hosting provider if it exists.
// If this matches, these contact details should be preferred over the
// registrar and hosting provider.
func IsSharedHostingProvider(u *url.URL) (bool, ProviderContact) {
	for _, m := range SharedHosts {
		if m.Matches(u.Host) {
			return true, m.Contact
		}
	}
	return false, nil
}

// Matches content served by shared hosting providers i.e. where the abusive content
// is not served by the domain/server owner.
//
// Try to keep this sorted alphabetically by ProviderName
var SharedHosts = []Matcher{
	{OnlineForm{"000webhost", "https://www.000webhost.com/report-abuse"}, isSubDomainOf("000webhost.com", "000webhostapp.com")},
	{AbuseEmail{"Adobe", "hellospark@adobe.com"}, isSubDomainOf("spark.adobe.com")},
	{OnlineForm{"Bitly", "https://bitly.is/reporting-abuse"}, isSubDomainOf("bit.ly")},
	{OnlineForm{"Blogger", "https://support.google.com/blogger/answer/76315"}, isSubDomainOf("blogger.com", "blogspot.com")},
	{OnlineForm{"ChangeIP", "https://www.changeip.com/contact-us.php"}, isSubDomainOf("dynamic-dns.net", "longmusic.com", "wikaba.com", "zzux.com", "dumb1.com", "onedumb.com", "youdontcare.com", "yourtrap.com", "2waky.com", "sexidude.com", "mefound.com", "organiccrap.com", "toythieves.com", "justdied.com", "jungleheart.com", "mrbasic.com", "mrbonus.com", "x24hr.com", "dns04.com", "dns05.com", "zyns.com", "my03.com", "fartit.com", "itemdb.com", "instanthq.com", "xxuz.com", "jkub.com", "itsaol.com", "faqserv.com", "jetos.com", "qpoe.com", "qhigh.com", "vizvaz.com", "mrface.com", "isasecret.com", "mrslove.com", "otzo.com", "americanunfinished.com", "serveusers.com", "serveuser.com", "freetcp.com", "ddns.info", "ns01.info", "ns02.info", "myftp.info", "mydad.info", "mymom.info", "mypicture.info", "myz.info", "squirly.info", "toh.info", "xxxy.info", "freewww.info", "freeddns.com", "myddns.com", "dynamicdns.biz", "ns01.biz", "ns02.biz", "xxxy.biz", "sexxxy.biz", "freewww.biz", "www1.biz", "dhcp.biz", "edns.biz", "ftp1.biz", "mywww.biz", "gr8domain.biz", "gr8name.biz", "ftpserver.biz", "wwwhost.biz", "moneyhome.biz", "port25.biz", "esmtp.biz", "dsmtp.biz", "sixth.biz", "ninth.biz", "misecure.com", "got-game.org", "bigmoney.biz", "dns2.us", "dns1.us", "ns02.us", "ns01.us", "changeip.us", "changeip.biz", "almostmy.com", "ocry.com", "ourhobby.com", "dnsfailover.net", "ygto.com", "ddns.ms", "ddns.us", "gettrials.com", "25u.com", "4dq.com", "4pu.com", "3-a.net", "dsmtp.com", "dsmtp.com", "mynumber.org", "ns1.name", "ns2.name", "ns3.name", "rebatesrule.net", "ezua.com", "sendsmtp.com", "ssmailer.com", "trickip.net", "trickip.org", "dnsrd.com", "lflinkup.com", "lflinkup.net", "lflinkup.org", "lflink.com", "dns-dns.com", "b0tnet.com", "proxydns.com", "changeip.net", "mysecondarydns.com", "changeip.org", "dns-stuff.com", "dynssl.com", "mylftv.com", "mynetav.com", "mynetav.net", "mynetav.org", "dns-report.com", "homingbeacon.net", "ikwb.com", "acmetoy.com", "ddns.mobi", "dnset.com", "as19557.net", "toshibanetcam.com", "authorizeddns.net", "authorizeddns.org", "authorizeddns.us", "cleansite.biz", "cleansite.info", "cleansite.us", "https443.net", "https443.org", "mypop3.net", "mypop3.org", "ssl443.org", "iownyour.biz", "iownyour.org", "onmypc.biz", "onmypc.info", "onmypc.net", "onmypc.org", "onmypc.us", "dubya.info", "dubya.us", "dubya.biz", "dubya.net", "changeip.co", "wwwhost.us")},
	{OnlineForm{"Cloudflare", "https://www.cloudflare.com/abuse/form"}, isSubDomainOf("workers.dev")},
	{AbuseEmail{"Glitch", "support@glitch.com"}, isSubDomainOf("glitch.me", "glitch.com")},
	{OnlineForm{"GoDaddy", "https://supportcenter.godaddy.com/AbuseReport"}, isSubDomainOf("godaddysites.com")},
	{OnlineForm{"Google Cloud", "https://support.google.com/code/contact/cloud_platform_report"}, isSubDomainOf("appspot.com", "googleapis.com", "web.app")},
	{OnlineForm{"Google Sites", "https://support.google.com/docs/answer/2463296?hl=en-GB#zippy=%2Cgoogle-sites"}, isSubDomainOf("sites.google.com")},
	{AbuseEmail{"IBM", "abuse@softlayer.com"}, isSubDomainOf("appdomain.cloud")},
	{OnlineForm{"Jimdo", "https://jimdo-legal.zendesk.com/hc/en-us/requests/new?ticket_form_id=239123"}, isSubDomainOf("jimdosite.com")},
	{OnlineForm{"Microsoft", "https://msrc.microsoft.com/report/abuse"}, isSubDomainOf("blob.core.windows.net")},
	{AbuseEmail{"Replit", "contact@repl.it"}, isSubDomainOf("repl.co")},
	{AbuseEmail{"Netlify", "fraud@netlify.com"}, isSubDomainOf("netlify.app")},
	{OnlineForm{"Notion", "https://www.notion.so/Report-inappropriate-content-9feb9f2f9d8c40b1b7d289b155907de0"}, isSubDomainOf("notion.so", "notion.com")},
	{AbuseEmail{"Square", "spoof@squareup.com"}, isSubDomainOf("square.site")},
	{OnlineForm{"Weebly", "https://www.weebly.com/uk/spam"}, isSubDomainOf("weebly.com")},
	{OnlineForm{"Yola", "https://helpcenter.yola.com/hc/en-us/requests/new?ticket_form_id=360001504300"}, isSubDomainOf("yolasite.com")},
}

func isSubDomainOf(domains ...string) func(string) bool {
	return func(abusiveDomain string) bool {
		for _, domain := range domains {
			if abusiveDomain == domain || strings.HasSuffix(abusiveDomain, "."+domain) {
				return true
			}
		}
		return false
	}
}
