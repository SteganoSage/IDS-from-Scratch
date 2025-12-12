#ifndef RULE_HPP
#define RULE_HPP

#include <string>
#include <vector>
#include <regex>

struct Rule {
    std::string raw_header;      // header before '('
    std::string msg;
    int sid = -1;
    std::vector<std::string> contents;      // literal contents (unescaped)
    std::vector<bool> content_nocase;       // parallel: whether this content has nocase
    std::vector<std::regex> pcre_patterns;  // compiled regex patterns
    std::vector<std::string> pcre_mods;     // modifiers for each pcre pattern
};

#endif // RULE_HPP
