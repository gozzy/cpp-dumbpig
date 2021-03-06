#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <string>
#include <vector>
#include <iostream>

#include "rule_checker.h"
#include <boost/tokenizer.hpp>

using namespace std;

static vector<string> my_split(string str, string separators, size_t max_tokens, char cat_sym = ' ')
{
	vector<string> toks;
	boost::split(toks, str, boost::is_any_of(separators), boost::token_compress_on);

	if (toks.size() > max_tokens) {
		for (size_t i = max_tokens; i < toks.size(); i++) {
			toks[max_tokens - 1] += cat_sym + toks[i];
		}

		toks.erase(toks.begin() + max_tokens, toks.end());
	}

	return toks;
}

// Perform some checks and notify a user if rule is not good enough.
static int analyze_rule(const string proto, string src_port, string dst_port,
		const vector<string> configured, string &message)
{
	int res = RULE_OK;

	if ((boost::iequals(proto, "tcp") || boost::iequals(proto, "udp")) &&
		(boost::iequals(src_port, "any") && boost::iequals(dst_port, "any"))) {
		message = "- Rule without port numbers - it'll be really slow\n";
		res = RULE_HAS_WARNINGS;
	}

	if (boost::iequals(proto, "ip") &&
		(find(configured.begin(), configured.end(), "content")    == configured.end()) &&
		(find(configured.begin(), configured.end(), "uricontent") == configured.end()) &&
		(find(configured.begin(), configured.end(), "pcre")       == configured.end()) &&
		(find(configured.begin(), configured.end(), "ip_proto")   == configured.end())) {
		message += "- IP rule without content match - it's better to use firewall for this\n";
		res = RULE_HAS_WARNINGS;
	}

	if ((boost::iequals(proto, "tcp") || boost::iequals(proto, "udp")) &&
		(find(configured.begin(), configured.end(), "content")    == configured.end()) &&
		(find(configured.begin(), configured.end(), "uricontent") == configured.end()) &&
		(find(configured.begin(), configured.end(), "byte_test")  == configured.end()) &&
		(find(configured.begin(), configured.end(), "dsize")      == configured.end()) &&
		(find(configured.begin(), configured.end(), "flags")      == configured.end())) {
		message += "- TCP/UDP rule without deep packet checks - it's better to use firewall for this\n";
		res = RULE_HAS_WARNINGS;
	}

	if (boost::iequals(proto, "tcp") &&
		(find(configured.begin(), configured.end(), "flow") == configured.end())) {
		message += "- TCP protocol without flow checking. Consider adding 'flow' keyword to provide better state tracking\n";
		res = RULE_HAS_WARNINGS;
	}

	if (boost::iequals(proto, "ip") &&
		(find(configured.begin(), configured.end(), "flow") != configured.end())) {
		message += "- IP protocol with flow checking - consider changing protocol to TCP or UDP\n";
		res = RULE_HAS_WARNINGS;
	}

	if ((find(configured.begin(), configured.end(), "pcre") != configured.end()) &&
		(find(configured.begin(), configured.end(), "pcre") == configured.end()) &&
		(find(configured.begin(), configured.end(), "pcre") == configured.end())) {
		message += "- PCRE matching without 'content' or 'uricontent' keywords - it'll cause a performance hit\n";
		res = RULE_HAS_WARNINGS;
	}

	return res;
}

static int parse_and_analyze_rule_options(const string proto, const string src_port,
	const string dst_port, string str, string &message)
{
	// No options.
	if (str.empty()) {
		return RULE_OK;
	}

	if ((str[0] != '(') || (str[str.length() - 1] != ')')) {
		message += "- Rule options must be enclosed in '(' and ')'\n";
		return RULE_HAS_ERRORS;
	}

	// Remove surrounding braces.
	str.erase(0, 1);
	str.erase(str.length() - 1, 1);

	vector<string> options;
	vector<string> configured;

	boost::split(options, str, boost::is_any_of(";"), boost::token_compress_on);

	bool found = false;

	for (const string &opt : options) {
		vector<string> subopts = my_split(opt, ":", 2, ':');
		boost::trim(subopts[0]);

		if (subopts[0].empty()) {
			continue;
		}

		if (subopts.size() > 1) {
			boost::trim(subopts[1]);
		}

		for (size_t j = 0; rule_options[j].name != nullptr; j++) {
			if (boost::iequals(rule_options[j].name, subopts[0])) {
				if ((find(configured.begin(), configured.end(), subopts[0]) != configured.end()) &&
					rule_options[j].only_once) {
					message += "- Option '" + subopts[0] + "' may be specified only once\n";
				}

				if (rule_options[j].args_required && (subopts.size() < 2)) {
					message += "- Option '" + subopts[0] + "' requires an argument\n";
				} else if (rule_options[j].arg_checker) {
					rule_options[j].arg_checker(subopts[0], subopts[1], message);
				}

				configured.push_back(subopts[0]);
				found = true;
				break;
			}
		}

		if (!found) {
			message += "- Unknown option: " + subopts[0] + "\n";
		}

		found = false;
	}

	if (boost::iequals(proto, "ip") && (!boost::iequals(src_port, "any") ||
		!boost::iequals(dst_port, "any"))) {
		message += "- IP protocol with port numbers - invalid syntax. IP protocol has no port numbers, consider using TCP or UDP\n";
	}

	if (find(configured.begin(), configured.end(), "sid") == configured.end()) {
		message += "- No SID number. Please add 'sid' keyword\n";
	}

	if (find(configured.begin(), configured.end(), "rev") == configured.end()) {
		message += "- No revision number. Please add 'rev' keyword\n";
	}

	if (find(configured.begin(), configured.end(), "classtype") == configured.end()) {
		message += "- No classification specified. Please add 'classtype' keyword for correct classification and priority rating\n";
	}

	if (!boost::iequals(proto, "icmp") && (find(configured.begin(), configured.end(), "icode") != configured.end())) {
		message += "- ICMP options on non-ICMP rule\n";
	}

	if (message.length()) {
		return RULE_HAS_ERRORS;
	}

	return analyze_rule(proto, src_port, dst_port, configured, message);
}

int process_rule(const string rule, string &message)
{
	if (rule.empty()) {
		return RULE_HAS_ERRORS;
	}

	message = "";

	vector<string> toks = my_split(rule, " \t", 8);

	if (toks.size() < 8) {
		cout << "Bad rule: " << rule << endl;
		return RULE_HAS_ERRORS;
	}

	// toks[0] - action
	// toks[1] - protocol
	// toks[2] - source address
	// toks[3] - source port
	// toks[4] - direction
	// toks[5] - destination address
	// toks[6] - destination port
	// toks[7] - rule options

	int res = parse_and_analyze_rule_options(toks[1], toks[3], toks[6], toks[7], message);

	if (message[message.length() - 1] == '\n') {
		message.erase(message.length() - 1);
	}

	return res;
}
