#include <regex>
#include <cstdio>
#include "arg_checkers.h"

using namespace std;

bool str_arg_checker(string opt, string arg, string &message)
{
	if ((arg[0] != '"') || (arg[arg.length() - 1] != '"')) {
		message += "- Value of option '" + opt + "' must be enclosed in '\"'\n";
		return false;
	}

	arg.erase(0, 1);
	arg.erase(arg.length() - 1, 1);

	if (arg.empty()) {
		message += "- Value of option '" + opt + "' is empty\n";
		return false;
	}

	return true;
}

bool pcre_arg_checker(string opt, string arg, string &message)
{
	if ((arg[0] != '"') || (arg[arg.length() - 1] != '"')) {
		message += "- Regular expression must be enclosed in '\"'\n";
		return false;
	}

	arg.erase(0, 1);
	arg.erase(arg.length() - 1, 1);

	if (arg.empty()) {
		message += "- Regular expression is empty\n";
		return false;
	}

	try {
		regex expr(arg);
	}
	catch (const exception &e) {
		message += "- Invalid regular expression: " + arg + " (" + e.what() + ")\n";
		return false;
	}

	return true;
}

bool uint_arg_checker(string opt, string arg, string &message)
{
	if (count_if(arg.begin(), arg.end(), not1(ptr_fun(::isdigit)))) {
		message += "- Invalid argument to '" + opt + "' option: " + arg + ". Must be a positive integer\n";
		return false;
	}

	return true;
}

static bool check_regex(string opt, string arg, string expr, string &message)
{
	if (!regex_match(arg, regex(expr))) {
		message += "- Invalid argument to '" + opt + "'\n";
		return false;
	}

	return true;
}

bool reference_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*([\\w\\d]+)\\s*,\"?\\s*\"?\\s*([\\w\\d\\-_\\.\\/\\?\\=]+)\"?\\s*\"?", message);
}

bool fragoffset_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(?:(<|>))?\\s*(\\d+)", message);
}

bool fragbits_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(?:([\\+\\*!]))?\\s*([MDR]+)", message);
}

bool classtype_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*([\\w[_\\w\\d\\-]*)\\s*$", message);
}

bool isdataat_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*!?([^\\s,]+)\\s*(,\\s*relative)?\\s*(,\\s*rawbytes\\s*)?\\s*$", message);
}

bool ttl_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(\\d*)?\\s*([-<>=]+)?\\s*(\\d+)?\\s*$", message);
}

bool detection_filter_arg_checker(string opt, string arg, string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*(track|count|seconds)\\s+(by_src|by_dst|\\d+)\\s*,\\s*(track|count|seconds)"
		"\\s+(by_src|by_dst|\\d+)\\s*,\\s*(track|count|seconds)\\s+(by_src|by_dst|\\d+)\\s*$",
		message);
}

bool threshold_arg_checker(string opt, string arg, string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|\\d+)\\s*,\\s*"
		"(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|\\d+)\\s*,\\s*"
		"(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|\\d+)\\s*,\\s*"
		"(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|\\d+)\\s*",
		message);
}

bool tag_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(host|session)\\s*(,\\s*(\\d+)\\s*,\\s*(packets|bytes|seconds)\\s*(,\\s*(src|dst))?\\s*)?$", message);
}

bool flow_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*([\\w_]+)\\s*(?:,\\s*([\\w_]+))?\\s*(?:,\\s*([\\w_]+))?\\s*$", message);
}

bool dce_iface_arg_checker(string opt, string arg, string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*([\\d\\w]{8}-[\\d\\w]{4}-[\\d\\w]{4}-[\\d\\w]{4}"
		"-[\\d\\w]{12})(?:\\s*,(<|>|=|!)(\\d{1,5}))?(?:\\s*,(any_frag))?\\s*$",
		message);
}

bool dce_opnum_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(\\d{1,5}(\\s*-\\s*\\d{1,5}\\s*)?)(,\\s*\\d{1,5}(\\s*-\\s*\\d{1,5})?\\s*)*$", message);
}

bool ssl_version_arg_checker(string opt, string arg, string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*(!?[\\w\\d.]+)\\s*,?\\s*(!?[\\w\\d.]+)?\\s*\\,?\\s*"
		"(!?[\\w\\d.]+)?\\s*,?\\s*(!?[\\w\\d.]+)?\\s*,?\\s*(!?[\\w\\d.]+)?\\s*$",
		message);
}

bool ssl_state_arg_checker(string opt, string arg, string &message)
{
	return (check_regex(opt, arg, "^\\s*([_\\w\\d]+)(.*)$", message) || check_regex(opt, arg, "^(?:\\s*[|]\\s*([_\\w\\d]+))(.*)$", message));
}

bool tos_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(!?\\s*\\d{1,3}|!?\\s*[xX][0-9a-fA-F]{1,2})\\s*$", message);
}

bool flowbits_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "([a-z]+)(?:,(.*))?", message);
}

bool dsize_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(<|>)?\\s*(\\d{1,5})\\s*(?:(<>)\\s*(\\d{1,5}))?\\s*$", message);
}

bool ip_proto_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*([!<>]?)\\s*([^\\s]+)\\s*$", message);
}

bool byte_jump_arg_checker(string opt, string arg, string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*"
		"([^\\s,]+\\s*,\\s*[^\\s,]+)"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?"
		"\\s*$",
		message);
}

bool byte_test_arg_checker(string opt, string arg, string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*"
		"([^\\s,]+)"
		"\\s*,\\s*(\\!?)\\s*([^\\s,]*)"
		"\\s*,\\s*([^\\s,]+)"
		"\\s*,\\s*([^\\s,]+)"
		"(?:\\s*,\\s*([^\\s,]+))?"
		"(?:\\s*,\\s*([^\\s,]+))?"
		"(?:\\s*,\\s*([^\\s,]+))?"
		"(?:\\s*,\\s*([^\\s,]+))?"
		"(?:\\s*,\\s*([^\\s,]+))?"
		"\\s*$",
		message);
}

bool ipopts_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "\\S\\w", message);
}

bool urilen_arg_checker(string opt, string arg, string &message)
{
	return check_regex(
		opt,
		arg,
		"^(?:\\s*)(<|>)?(?:\\s*)(\\d{1,5})(?:\\s*)(?:(<>)(?:\\s*)"
		"(\\d{1,5}))?\\s*(?:,\\s*(norm|raw))?\\s*$",
		message);
}

bool icode_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(<|>)?\\s*(\\d+)\\s*(?:<>\\s*(\\d+))?\\s*$", message);
}

bool itype_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(<|>)?\\s*(\\d+)\\s*(?:<>\\s*(\\d+))?\\s*$", message);
}

bool flags_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "^\\s*(?:([\\+\\*!]))?\\s*([SAPRFU120CE\\+\\*!]+)(?:\\s*,\\s*([SAPRFU12CE]+))?\\s*$", message);
}

bool iprep_arg_checker(string opt, string arg, string &message)
{
	return check_regex(opt, arg, "\\s*(any|src|dst|both)\\s*,\\s*([\\w\\d\\-_]+)\\s*,\\s*(<|>|=)\\s*,\\s*(12[0-7]|1[01]\\d|[1-9]\\d|[1-9])\\s*", message);
}
