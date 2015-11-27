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
	{ "metadata",         true,  false, nullptr },
	{ "msg",              true,  true,  nullptr },
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
	{ "flowbits",         true,  false, flowbits_arg_checker },
	{ "distance",         true,  false, nullptr },
	{ "within",           true,  false, nullptr },
	{ "offset",           true,  false, nullptr },
	{ "depth",            true,  false, uint_arg_checker },
	{ "dsize",            true,  true,  dsize_arg_checker },
	{ "byte_test",        true,  false, byte_test_arg_checker },
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
	{ "asn1",             true,  true,  nullptr },
	{ "dce_iface",        true,  true,  dce_iface_arg_checker },
	{ "dce_opnum",        true,  true,  dce_opnum_arg_checker },
	{ "icmp_id",          true,  true,  uint_arg_checker },
	{ "icmp_seq",         true,  true,  uint_arg_checker },
	{ "http_encode",      true,  true,  nullptr },
	{ "ssl_version",      true,  true,  ssl_version_arg_checker },
	{ "ssl_state",        true,  true,  ssl_state_arg_checker },
	{ "tos",              true,  true,  tos_arg_checker },
	{ "iprep",            true,  false, iprep_arg_checker },
	{ "app-layer-event",  true,  true,  nullptr },
	{ "stream-event",     true,  true,  nullptr },
	{ "flowint",          true,  false, nullptr },

	// Argless options
	{ "http_method",      false, true,  nullptr },
	{ "ftpbounce",        false, true,  nullptr },
	{ "file_data",        false, true,  nullptr },
	{ "nocase",           false, false, nullptr },
	{ "rawbytes",         false, true,  nullptr },
	{ "dce_stub_data",    false, true,  nullptr },
	{ "fast_pattern",     false, true,  nullptr },
	{ "http_client_body", false, false, nullptr },
	{ "http_header",      false, false, nullptr },
	{ "http_raw_cookie",  false, true,  nullptr },
	{ "http_raw_header",  false, true,  nullptr },
	{ "http_uri",         false, false, nullptr },
	{ "http_stat_code",   false, true,  nullptr },
	{ "http_stat_msg",    false, true,  nullptr },
	{ "http_cookie",      false, true,  nullptr },
	{ "sameip",           false, true,  nullptr },
	{ "noalert",          false, false, nullptr },

	{ nullptr,            false, false, nullptr }
};

int process_rule(const std::string rule, std::string &message);
