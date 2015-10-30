#include <boost/regex.hpp>
#include <cstdio>
#include "arg_checkers.h"

bool str_arg_checker(std::string opt, std::string arg, std::string &message)
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

bool pcre_arg_checker(std::string opt, std::string arg, std::string &message)
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
		boost::regex expr(arg, boost::regex::perl);
	}
	catch (const std::exception &e) {
		message += "- Invalid regular expression: " + arg + " (" + e.what() + ")\n";
		return false;
	}

	return true;
}

bool uint_arg_checker(std::string opt, std::string arg, std::string &message)
{
	if (std::count_if(arg.begin(), arg.end(), std::not1(std::ptr_fun(::isdigit)))) {
		message += "- Invalid argument to '" + opt + "' option: " + arg + ". Must be a positive integer\n";
		return false;
	}

	return true;
}

static bool check_regex(std::string opt, std::string arg, std::string expr, std::string &message)
{
	if (!boost::regex_match(arg, boost::regex(expr))) {
		message += "- Invalid argument to '" + opt + "'\n";
		return false;
	}

	return true;
}

bool reference_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*([A-Za-z0-9]+)\\s*,\"?\\s*\"?\\s*([a-zA-Z0-9\\-_\\.\\/\\?\\=]+)\"?\\s*\"?", message);
}

bool fragoffset_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(?:(<|>))?\\s*([0-9]+)", message);
}

bool fragbits_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(?:([\\+\\*!]))?\\s*([MDR]+)", message);
}

bool classtype_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*([a-zA-Z][_a-zA-Z0-9-]*)\\s*$", message);
}

bool isdataat_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*!?([^\\s,]+)\\s*(,\\s*relative)?\\s*(,\\s*rawbytes\\s*)?\\s*$", message);
}

bool ttl_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*([0-9]*)?\\s*([-<>=]+)?\\s*([0-9]+)?\\s*$", message);
}

bool detection_filter_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*(track|count|seconds)\\s+(by_src|by_dst|\\d+)\\s*,\\s*(track|count|seconds)"
		"\\s+(by_src|by_dst|\\d+)\\s*,\\s*(track|count|seconds)\\s+(by_src|by_dst|\\d+)\\s*$",
		message);
}

bool threshold_arg_checker(std::string opt, std::string arg, std::string &message)
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

bool tag_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(host|session)\\s*(,\\s*(\\d+)\\s*,\\s*(packets|bytes|seconds)\\s*(,\\s*(src|dst))?\\s*)?$", message);
}

bool flow_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*([A-z_]+)\\s*(?:,\\s*([A-z_]+))?\\s*(?:,\\s*([A-z_]+))?\\s*$", message);
}

bool dce_iface_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*([0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}"
		"-[0-9a-zA-Z]{12})(?:\\s*,(<|>|=|!)([0-9]{1,5}))?(?:\\s*,(any_frag))?\\s*$",
		message);
}

bool dce_opnum_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*([0-9]{1,5}(\\s*-\\s*[0-9]{1,5}\\s*)?)(,\\s*[0-9]{1,5}(\\s*-\\s*[0-9]{1,5})?\\s*)*$", message);
}

bool ssl_version_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(
		opt,
		arg,
		"^\\s*(!?[A-z0-9.]+)\\s*,?\\s*(!?[A-z0-9.]+)?\\s*\\,?\\s*"
		"(!?[A-z0-9.]+)?\\s*,?\\s*(!?[A-z0-9.]+)?\\s*,?\\s*(!?[A-z0-9.]+)?\\s*$",
		message);
}

bool ssl_state_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return (check_regex(opt, arg, "^\\s*([_a-zA-Z0-9]+)(.*)$", message) || check_regex(opt, arg, "^(?:\\s*[|]\\s*([_a-zA-Z0-9]+))(.*)$", message));
}

bool tos_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(!?\\s*[0-9]{1,3}|!?\\s*[xX][0-9a-fA-F]{1,2})\\s*$", message);
}

bool flowbits_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "([a-z]+)(?:,(.*))?", message);
}

bool dsize_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(<|>)?\\s*([0-9]{1,5})\\s*(?:(<>)\\s*([0-9]{1,5}))?\\s*$", message);
}

bool ip_proto_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*([!<>]?)\\s*([^\\s]+)\\s*$", message);
}

bool byte_jump_arg_checker(std::string opt, std::string arg, std::string &message)
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

bool byte_test_arg_checker(std::string opt, std::string arg, std::string &message)
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

bool ipopts_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "\\S[A-z]", message);
}

bool urilen_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(
		opt,
		arg,
		"^(?:\\s*)(<|>)?(?:\\s*)([0-9]{1,5})(?:\\s*)(?:(<>)(?:\\s*)"
		"([0-9]{1,5}))?\\s*(?:,\\s*(norm|raw))?\\s*$",
		message);
}

bool icode_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(<|>)?\\s*([0-9]+)\\s*(?:<>\\s*([0-9]+))?\\s*$", message);
}

bool itype_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(<|>)?\\s*([0-9]+)\\s*(?:<>\\s*([0-9]+))?\\s*$", message);
}

bool flags_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "^\\s*(?:([\\+\\*!]))?\\s*([SAPRFU120CE\\+\\*!]+)(?:\\s*,\\s*([SAPRFU12CE]+))?\\s*$", message);
}

bool iprep_arg_checker(std::string opt, std::string arg, std::string &message)
{
	return check_regex(opt, arg, "\\s*(any|src|dst|both)\\s*,\\s*([\\w\\d\\-_]+)\\s*,\\s*(<|>|=)\\s*,\\s*(12[0-7]|1[01][0-9]|[1-9][0-9]|[1-9])\\s*", message);
}
