package core

import "regexp"

const (
	GENERIC = "generic"
)

var generic = &Plugin{
	Name: GENERIC,
	Desc: "A plugin that detects webshell of python or perl type",
	Decoders: []Decoder{
		{
			Name:       "generic/url_decode",
			Regex:      regexp.MustCompile(`(?i)(https?(?:%3A%2F%2F|://%).+(?:\s+|'|"|=|\?))`),
			DataFilter: regexp.MustCompile(`(?i)(https?(?:%3A%2F%2F|://%).+(?:\s+|'|"|=|\?))`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{UrlDecode},
		}, {
			Name:       "generic/base64_decode",
			Regex:      regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]{8,}(?:'|"))`),
			DataFilter: regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]{8,}(?:'|"))`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{DecodeBase64},
		}, {
			Name:       "generic/multiline_base64_decode",
			Regex:      regexp.MustCompile(`(?i)(?:(?:'|')(?:[A-Za-z0-9+\/=]{4,})+(?:'|")\.?(?:\r|\n)?)+`),
			DataFilter: regexp.MustCompile(`(?i)(?:(?:'|')(?:[A-Za-z0-9+\/=]{4,})+(?:'|")\.?(?:\r|\n)?)+`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\r\n", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"\n", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"\r", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{".", "", -1}},
			},
			Functions: []BaseFunc{DecodeBase64},
		},
	},
	Tags: []Tag{
		{Name: "generic/execution", Regex: regexp.MustCompile(`(?i)(?:\w+\.run\("%comspec% /c)`), Scored: 45},
		{Name: "generic/keywords", Regex: regexp.MustCompile(`(?i)(?:xp_cmdshell|Database\s+Dump|ShiSanObjstr|Net\s+Sploit|SQLI\+Scan|shell\s?code|envlpass|files?man|c0derz\s?shell|md5\s?cracker|umer\s?rock|asp\s?cmd\s?shell|JspSpy|uZE\s?Shell|AK-74\s?Security\s?Team\s?Web\s?Shell|WinX\s?Shell|PHP C0nsole|cfmshell|cmdshell|Gamma\s?Web\s?Shell|ASPXSpy|IISSpy|Webshell|ASPX?\s?Shell|STNC WebShell|GRP\s?WebShell|National Cracker Crew)`), Scored: 16, Repeat: true},
		{Name: "generic/domain", Regex: regexp.MustCompile(`(?i)(https?://(?:\d+\.\d+\.\d+\.\d+|\w+(?:\.\w+\.\w+|\.\w+)?)[/\w+\?=\.]+)`), Scored: 10, Repeat: true},
		{Name: "generic/embedded_executable", Regex: regexp.MustCompile(`(?i)(?:(?:0x)?4D5A)`), Scored: 10, Repeat: true},
		{Name: "generic/reconnaissance", Regex: regexp.MustCompile(`(?i)(?:tasklist|netstat|ipconfig|whoami|net\s+(?:localgroup|user)(?:\s|\w)+/add|net\s+start\s+)`), Scored: 10, Repeat: true},
		{Name: "generic/commands", Regex: regexp.MustCompile(`(?i)(?:[wc]script\.(?:shell|network)|(?:cmd|powershell|[wc]script)(?:\.exe)?|cmd\.exe\s+/c)`), Scored: 15, Repeat: true},
		{Name: "generic/registry_persistence", Regex: regexp.MustCompile(`(?i)(?:\\currentversion\\(?:run|runonce))`), Scored: 10, Repeat: true},
		{Name: "generic/defense_evasion", Regex: regexp.MustCompile(`(?i)(?:strpos\(\$_SERVER\['HTTP_USER_AGENT'\],'Google'\))`), Scored: 50},
		{Name: "generic/c_embedded_code", Regex: regexp.MustCompile(`(?i)(?:socket\(AF_INET,SOCK_STREAM|bind\(|listen\(|daemon\(1,0\))`), Scored: 20},
		{Name: "generic/perl_embedded_code", Regex: regexp.MustCompile(`(?i)(?:getprotobyname\('tcp'\))|exec\s+\{'/bin/sh'\}\s+'-bash'`), Scored: 40},
		{Name: "generic/python_embedded_code", Regex: regexp.MustCompile(`(?i)(?:)cgitb\.enable\(\)|print_exc\(|import\ssubprocess|os\.system\(|subprocess\.Popen\(|urllib\.urlretrieve\(`), Scored: 12, Repeat: true},
		{Name: "generic/tcp_connected", Regex: regexp.MustCompile(`/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+`), Scored: 55},
	},
	Supports: []string{},
}
