#include <string>
#include <cstdio>
#include <fstream>
#include <cerrno>
#include <iostream>
#include <boost/program_options.hpp>
#include "rule_checker.h"

int main(int argc, char **argv)
{
	namespace po = boost::program_options;
	std::string filename;

	po::options_description desc(
		"A simple dumbpig-like snort/suricata rules checker\n\n"
		"Allowed options"
	);

	desc.add_options()
		("help,h",
			"produce help message")
		("filename,f",
			po::value<std::string>()->required(),
			"rules file name,\nuse dash (-) for stdin")
		;

	try {
		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return 0;
		}

		if (vm.count("filename")) {
			filename = vm["filename"].as<std::string>();
		}
	} catch (const std::exception &e) {
		std::cout << e.what() << std::endl;
		std::cout << "Use '-h' option for help" << std::endl;
		return 1;
	}

	std::istream *p_input = &std::cin;
	std::ifstream in_file;

	if (filename != "-") {
		in_file.open(filename.c_str(), std::ifstream::in);

		if (!in_file) {
			std::cerr << "Failed to open file '" << filename.c_str() << ": "
				<< strerror(errno) << std::endl;
			return 2;
		}

		p_input = &in_file;
	}

	std::string message;
	std::string rule_str;

	while(std::getline(*p_input, rule_str)) {
		process_rule(rule_str, message);
		std::cout << "Rule: " << rule_str << std::endl;
		std::cout << message << "\n" << std::endl;
	}

	return 0;
}
