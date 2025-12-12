#ifndef RULEPARSER_HPP
#define RULEPARSER_HPP

#include "Rules.hpp"
#include <string>
#include <vector>

class RuleParser {
public:
    // parse a rules file, return parsed rules (only those that contain content/pcre)
    std::vector<Rule> parse_file(const std::string &path);

    // try parse a single rule line, return true if it was a valid rule line and filled 'r'
    static bool parse_rule_line(const std::string &line, Rule &r);
};

#endif // RULEPARSER_HPP
