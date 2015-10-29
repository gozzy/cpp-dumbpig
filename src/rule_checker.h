#pragma once
#include <string>
#include "arg_checkers.h"

#define RULE_HAS_ERRORS		-1
#define RULE_OK			0
#define RULE_HAS_WARNINGS	1

typedef bool (*ParseArgFunc)(std::string, std::string, std::string &);

typedef struct rule_options
{
	const char *name;
	bool args_required;
	bool only_once;
	ParseArgFunc arg_checker;
} type_rule_options;

static const type_rule_options rule_options[] = {
	// Options with arguments
	{ "activated_by",     true,  true,  uint_arg_checker },
	{ "activates",        true,  true,  uint_arg_checker },
	{ "classtype",        true,  true,  classtype_arg_checker },
	{ "count",            true,  true,  uint_arg_checker },
	{ "detection_filter", true,  true,  detection_filter_arg_checker },
	{ "gid",              true,  true,  uint_arg_checker },
	{ "logto",            true,  true,  str_arg_checker },
	{ "metadata",         true,  false, NULL },
	{ "msg",              true,  true,  NULL },
	{ "priority",         true,  true,  uint_arg_checker },
	{ "reference",        true,  false, reference_arg_checker },
	{ "rev",              true,  true,  uint_arg_checker },
	{ "sid",              true,  true,  uint_arg_checker },
	{ "tag",              true,  true,  tag_arg_checker },
	{ "threshold",        true,  true,  threshold_arg_checker },
	{ "content",          true,  false, str_arg_checker },
	{ "ttl",              true,  true,  ttl_arg_checker },
	{ "uricontent",       true,  true,  str_arg_checker },
	{ "pcre",             true,  true,  pcre_arg_checker },
	{ "flow",             true,  true,  flow_arg_checker },
	{ "flowbits",         true,  true,  flowbits_arg_checker },
	{ "distance",         true,  false, NULL },
	{ "within",           true,  false, NULL },
	{ "offset",           true,  false, NULL },
	{ "depth",            true,  false, uint_arg_checker },
	{ "dsize",            true,  true,  dsize_arg_checker },
	{ "byte_test",        true,  true,  byte_test_arg_checker },
	{ "byte_jump",        true,  true,  byte_jump_arg_checker },
	{ "isdataat",         true,  true,  isdataat_arg_checker },
	{ "ipopts",           true,  true,  ipopts_arg_checker },
	{ "itype",            true,  true,  itype_arg_checker },
	{ "icode",            true,  true,  icode_arg_checker },
	{ "flags",            true,  true,  flags_arg_checker },
	{ "urilen",           true,  true,  urilen_arg_checker },
	{ "fragbits",         true,  true,  fragbits_arg_checker },
	{ "fragoffset",       true,  true,  fragoffset_arg_checker },
	{ "seq",              true,  true,  uint_arg_checker },
	{ "ack",              true,  true,  uint_arg_checker },
	{ "window",           true,  true,  uint_arg_checker },
	{ "id",               true,  true,  uint_arg_checker },
	{ "ip_proto",         true,  true,  ip_proto_arg_checker },
	{ "asn1",             true,  true,  NULL },
	{ "dce_iface",        true,  true,  dce_iface_arg_checker },
	{ "dce_opnum",        true,  true,  dce_opnum_arg_checker },
	{ "icmp_id",          true,  true,  uint_arg_checker },
	{ "icmp_seq",         true,  true,  uint_arg_checker },
	{ "http_encode",      true,  true,  NULL },
	{ "ssl_version",      true,  true,  ssl_version_arg_checker },
	{ "ssl_state",        true,  true,  ssl_state_arg_checker },
	{ "tos",              true,  true,  tos_arg_checker },
	{ "iprep",            true,  false, iprep_arg_checker },

	// Argless options
	{ "http_method",      false, true,  NULL },
	{ "ftpbounce",        false, true,  NULL },
	{ "file_data",        false, true,  NULL },
	{ "nocase",           false, false, NULL },
	{ "rawbytes",         false, true,  NULL },
	{ "dce_stub_data",    false, true,  NULL },
	{ "fast_pattern",     false, true,  NULL },
	{ "http_client_body", false, false, NULL },
	{ "http_header",      false, false, NULL },
	{ "http_raw_cookie",  false, true,  NULL },
	{ "http_raw_header",  false, true,  NULL },
	{ "http_uri",         false, false, NULL },
	{ "http_stat_code",   false, true,  NULL },
	{ "http_stat_msg",    false, true,  NULL },
	{ "http_cookie",      false, true,  NULL },
	{ "sameip",           false, true,  NULL },

	{ NULL,               false, false, NULL }
};

int process_rule(const std::string rule, std::string &message);
