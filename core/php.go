package core

import "regexp"

const (
	PHP = "php"
)

var php = &Plugin{
	Name: PHP,
	Desc: "A plugin that detects webshell of php type",
	Decoders: []Decoder{
		{
			Name:       "php/base64_decode",
			Regex:      regexp.MustCompile(`(?i)(?:=|\s+)(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))`),
			DataFilter: regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{DecodeBase64},
		}, {
			Name:       "php/gz_inflate_base64_decode",
			Regex:      regexp.MustCompile(`(?i)(gzinflate\(base64_decode\('('?\"?[A-Za-z0-9+\/=]+'?\"?))\)`),
			DataFilter: regexp.MustCompile(`(?i)((?:'|")[A-Za-z0-9+\/=]+(?:'|"))`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{DecodeBase64, GzInflate},
		}, {
			Name:       "php/url_decode",
			Regex:      regexp.MustCompile(`(?i)(urldecode\('?"?[%\w+]+'?"?\))`),
			DataFilter: regexp.MustCompile(`(?i)((?:'|")'?"?[%\w+]+'?"?)`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{UrlDecode},
		}, {
			Name:       "php/dot_concatenation",
			Regex:      regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			DataFilter: regexp.MustCompile(`(?i).+(?:(?:'|")\.(?:'|")(?:\w+\.?)\w+(?:\s)?(?:/\w+\s+)?)+`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"\"", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"'", "", -1}},
			},
			Functions: []BaseFunc{},
		}, {
			Name:       "php/char_decode",
			Regex:      regexp.MustCompile(`(?:(?:\.chr\(\d+\))+|array\((?:\r|\n|\r\n|\n\r|\s+)chr\(\d+\)\.(chr\(\d+\)(?:\.|,)(?:\s+)?)+chr\(\d+\))`),
			DataFilter: regexp.MustCompile(`(?:(?:\.chr\(\d+\))+|chr\(\d+\)\.(chr\(\d+\)(?:\.|,)(?:\s+)?)+chr\(\d+\))`),
			PreDecodeActions: []Action{
				{Func: StringReplace, Arguments: []interface{}{"chr", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{" ", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{")", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{"(", "|", -1}},
				{Func: StringReplace, Arguments: []interface{}{",", "", -1}},
				{Func: StringReplace, Arguments: []interface{}{".", "", -1}},
			},
			Functions: []BaseFunc{CharDecode},
		},
	},
	Tags: []Tag{
		{Name: "php/functions_1", Regex: regexp.MustCompile(`(?i)(?:allow_url_fopen\(|fsockopen\(|getrusage\(|get_current_user\(|set_time_limit\(|getmyuid\(|getmypid\(|dl\(|leak\(|listen\(|chown\(|chgrp\(|realpath\(|link\(|exec\(|passthru\(|curl_init\()`), Scored: 40},
		{Name: "php/reconnaissance", Regex: regexp.MustCompile(`(?i)(?:@ini_get\("disable_functions"\)|gethostbyname\(|phpversion\(|disk_total_space\(|posix_getpwuid\(|posix_getgrgid\(|phpinfo\()`), Scored: 30},
		{Name: "php/database", Regex: regexp.MustCompile(`(?i)(?:'mssql_connect\('|ocilogon\(|mysql_list_dbs\(mysql_num_rows\(|mysql_dbname\(|mysql_create_db\(|mysql_drop_db\(|mysql_query\(|mysql_exec\()`), Scored: 20},
		{Name: "php/disk_operation", Regex: regexp.MustCompile(`(?i)(?:(?:\s|@)rename\(|(%s|@)chmod\(|(%s|@)fileowner\(|(%s|@)filegroup\(|fopen\(|fwrite\(\))`), Scored: 20, Repeat: true},
		{Name: "php/execution", Regex: regexp.MustCompile(`(?i)(?:(?:\s|\()(?:curl_exec\(|eval\(|exec\(|system\(|shell_exec\(|execute\(|passthru\()|(?:assert|array)\(\$_REQUEST\['?"?\w+"?'?\]|\$\{"?'?_REQUEST'?"?\})`), Scored: 50},
		{Name: "php/defense_evasion", Regex: regexp.MustCompile(`(?i)(?:gzinflate\(base64_decode\(|preg_replace\(|\(md5\(md5\(\$\w+\))`), Scored: 5, Repeat: true},
		{Name: "php/network_operation", Regex: regexp.MustCompile(`(?i)(?:fsockopen\()`), Scored: 10, Repeat: true},
		{Name: "php/functions_2", Regex: regexp.MustCompile(`(?i)function\_exists\s*\(\s*[\'|\"](popen|exec|proc\_open|system|passthru)+[\'|\"]\s*\)`), Scored: 40},
		{Name: "php/network", Regex: regexp.MustCompile(`(?i)((udp|tcp)\:\/\/(.*)\;)+`), Scored: 10, Repeat: true},
		{Name: "php/include_source", Regex: regexp.MustCompile(`(?i)(include|require|include\_once|require\_once)+\s*\(\s*[\'|\"](\w+)\.(jpg|gif|ico|bmp|png|txt|zip|rar|htm|css|js)+[\'|\"]\s*\)`), Scored: 12, Repeat: true},
		{Name: "php/file_operation", Regex: regexp.MustCompile(`(?i)\(\s*\$\_FILES\[(.*)\]\[(.*)\]\s*\,\s*\$\_(GET|POST|REQUEST|FILES)+\[(.*)\]\[(.*)\]\s*\)`), Scored: 13, Repeat: true},
		{Name: "php/execution_2", Regex: regexp.MustCompile(`eval\((.*)\$\_POST\[(.*)\](.*)\)`), Scored: 85},
		{Name: "php/execution_3", Regex: regexp.MustCompile(`(?i)(server.MapPath\(Request\[(.*)\](.*)\))`), Scored: 80},
		{Name: "php/execution_4", Regex: regexp.MustCompile(`(system\(|assert\(|eval\()(.*)\$\_(POST|REQUEST)\[`), Scored: 75},
	},
	Supports: []string{"php"},
}
