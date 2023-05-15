package core

import "regexp"

const (
	ASP = "asp"
)

var asp = &Plugin{
	Name: ASP,
	Desc: "A plugin that detects webshell of vbscript type",
	Decoders: []Decoder{
		{
			Name:       "asp/base64_decode",
			Regex:      regexp.MustCompile(`(?i)(?:=|\s+)(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))`),
			DataFilter: regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{DecodeBase64},
		}, {
			Name:       "asp/gz_inflate_base64_decode",
			Regex:      regexp.MustCompile(`(?i)(gzinflate\(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))\)`),
			DataFilter: regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{DecodeBase64, GzInflate},
		}, {
			Name:       "asp/comment_obfuscation_1",
			Regex:      regexp.MustCompile(`(?i).*(?:"|')\&(?:"|')\w+(?:"|')`),
			DataFilter: regexp.MustCompile(`(?i).*(?:"|')\&(?:"|')\w+(?:"|')`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{},
		}, {
			Name:       "asp/comment_obfuscation_2",
			Regex:      regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			DataFilter: regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{},
		}, {
			Name:       "asp/vbscript_encode",
			Regex:      regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			DataFilter: regexp.MustCompile(`(?i).*\+?(?:"|')\w+(?:"|')\+\w+\+(?:"|')\w+(?:"|')`),
			PreDecodeActions: []Action{
				{Func: StringReplaceWithRegex, Arguments: []interface{}{`(?i)(?:"|')\+\w+\+(?:"|')`, "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"+", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"\"++\"", "", -1}},
			},
			Functions: []BaseFunc{},
		},
	},
	Tags: []Tag{
		{Name: "asp/execution", Regex: regexp.MustCompile(`(?i)(?:e["+/*-]+v["+/*-]+a["+/*-]+l["+/*-]+\(|system\.diagnostics\.processstartinfo\(\w+\.substring\(|startinfo\.filename=\"?'?cmd\.exe"?'?|\seval\(request\.item\["?'?\w+"?'?\](?:,"?'?unsafe"?'?)?|execute(?:\(|\s+request\(\"\w+\"\))|RunCMD\(|\seval\(|COM\('?"?WScript\.(?:shell|network)"?'?|response\.write\()`), Scored: 80},
		{Name: "asp/command", Regex: regexp.MustCompile(`(?i)\w+\.(?:ExecuteNonQuery|CreateCommand)\(`), Scored: 20},
		{Name: "asp/disk_operations", Regex: regexp.MustCompile(`(?i)(?:createtextfile\(|server\.createobject\(\"Scripting\.FileSystemObject\"\))`), Scored: 50},
		{Name: "asp/suspicious", Regex: regexp.MustCompile(`(?i)(?:deletefile\(server\.mappath\(\"\w+\.\w+\"\)\)|language\s+=\s+vbscript\.encode\s+%>(?:\s*|\r|\n)<%\s+response\.buffer=true:server\.scripttimeout=|(?i)language\s+=\s+vbscript\.encode%><%\n?\r?server\.scripttimeout=|executeglobal\(|server\.createobject\(\w+\(\w{1,5},\w{1,5}\)\))`), Scored: 60},
		{Name: "asp/object_created", Regex: regexp.MustCompile(`(?i)server\.createobject\(\"(?:msxml2\.xmlhttp|microsoft\.xmlhttp|WSCRIPT\.SHELL|ADODB\.Connection)\"\)`), Scored: 55},
		{Name: "asp/suspicious_import", Regex: regexp.MustCompile(`(?i)name(?:space)?="(?:system\.(?:serviceprocess|threading|(?:net\.sockets)))"?"`), Scored: 50},
		{Name: "asp/process_threads", Regex: regexp.MustCompile(`(?:new\s+process\(\)|startinfo\.(?:filename|UseShellExecute|Redirect(?:StandardInput|StandardOutput|StandardError)|CreateNoWindow)|WaitForExit())`), Scored: 40},
		{Name: "asp/database", Regex: regexp.MustCompile(`(?:(?:SqlDataAdapter|SqlConnection|SqlCommand)\(|System\.Data\.SqlClient|System\.Data\.OleDb|OleDbConnection\(\))`), Scored: 30},
		{Name: "asp/behinder", Regex: regexp.MustCompile(`(?i)(session\.getValue\(.*AES.*\)|base64decoder|newInstance|session.Add\()`), Scored: 20, Repeat: true},
		{Name: "asp/execution_2", Regex: regexp.MustCompile(`eval\((.*)Request.Item\[(.*)\](.*)\)`), Scored: 85},
	},
	Supports: []string{"asp", "aspx"},
}
