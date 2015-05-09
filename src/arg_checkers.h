#pragma once
#include <string>

bool str_arg_checker              (std::string opt, std::string arg, std::string &message);
bool pcre_arg_checker             (std::string opt, std::string arg, std::string &message);
bool reference_arg_checker        (std::string opt, std::string arg, std::string &message);
bool uint_arg_checker             (std::string opt, std::string arg, std::string &message);
bool fragoffset_arg_checker       (std::string opt, std::string arg, std::string &message);
bool fragbits_arg_checker         (std::string opt, std::string arg, std::string &message);
bool classtype_arg_checker        (std::string opt, std::string arg, std::string &message);
bool isdataat_arg_checker         (std::string opt, std::string arg, std::string &message);
bool ttl_arg_checker              (std::string opt, std::string arg, std::string &message);
bool detection_filter_arg_checker (std::string opt, std::string arg, std::string &message);
bool threshold_arg_checker        (std::string opt, std::string arg, std::string &message);
bool tag_arg_checker              (std::string opt, std::string arg, std::string &message);
bool flow_arg_checker             (std::string opt, std::string arg, std::string &message);
bool dce_iface_arg_checker        (std::string opt, std::string arg, std::string &message);
bool dce_opnum_arg_checker        (std::string opt, std::string arg, std::string &message);
bool ssl_version_arg_checker      (std::string opt, std::string arg, std::string &message);
bool ssl_state_arg_checker        (std::string opt, std::string arg, std::string &message);
bool tos_arg_checker              (std::string opt, std::string arg, std::string &message);
bool flowbits_arg_checker         (std::string opt, std::string arg, std::string &message);
bool dsize_arg_checker            (std::string opt, std::string arg, std::string &message);
bool ip_proto_arg_checker         (std::string opt, std::string arg, std::string &message);
bool byte_jump_arg_checker        (std::string opt, std::string arg, std::string &message);
bool byte_test_arg_checker        (std::string opt, std::string arg, std::string &message);
bool ipopts_arg_checker           (std::string opt, std::string arg, std::string &message);
bool urilen_arg_checker           (std::string opt, std::string arg, std::string &message);
bool icode_arg_checker            (std::string opt, std::string arg, std::string &message);
bool itype_arg_checker            (std::string opt, std::string arg, std::string &message);
bool flags_arg_checker            (std::string opt, std::string arg, std::string &message);
