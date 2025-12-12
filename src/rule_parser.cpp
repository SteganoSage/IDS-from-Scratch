#include "Rule_Parser.hpp"
#include "Utils.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

bool RuleParser::parse_rule_line(const std::string &line, Rule &r) {
    std::string s = trim(line);
    if (s.empty()) return false;
    if (s[0] == '#') return false;
    auto open_paren = s.find('(');
    auto close_paren = s.rfind(')');
    if (open_paren == std::string::npos || close_paren == std::string::npos || close_paren <= open_paren) {
        return false;
    }
    r.raw_header = trim(s.substr(0, open_paren));
    std::string options = s.substr(open_paren + 1, close_paren - open_paren - 1);

    // split by semicolon ignoring semicolons inside quotes
    std::vector<std::string> tokens;
    std::string cur;
    bool in_quote = false;
    for (size_t i = 0; i < options.size(); ++i) {
        char c = options[i];
        if (c == '"' && (i == 0 || options[i-1] != '\\')) {
            in_quote = !in_quote;
            cur.push_back(c);
        } else if (c == ';' && !in_quote) {
            tokens.push_back(trim(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) tokens.push_back(trim(cur));

    for (const auto &tok_raw : tokens) {
        if (tok_raw.empty()) continue;
        auto tok = tok_raw;
        auto colon = tok.find(':');
        std::string key = (colon == std::string::npos) ? trim(tok) : trim(tok.substr(0, colon));
        std::string rest = (colon == std::string::npos) ? std::string() : trim(tok.substr(colon + 1));

        if (key == "msg" && !rest.empty()) {
            size_t p = 0; std::string val;
            if (parse_quoted(rest, p, val)) r.msg = unescape_snort_string(val);
        } else if (key == "sid" && !rest.empty()) {
            try { r.sid = std::stoi(rest); } catch(...) { r.sid = -1; }
        } else if (key == "content" && !rest.empty()) {
            size_t p = 0; std::string val;
            if (rest[0] == '"' && parse_quoted(rest, p, val)) {
                r.contents.push_back(unescape_snort_string(val));
                r.content_nocase.push_back(false);
            }
        } else if (key == "pcre" && !rest.empty()) {
            size_t p = 0;
            std::string pattern, mods;
            if (parse_pcre(rest, p, pattern, mods)) {
                bool icase = false;
                for (char c : mods) if (c == 'i') icase = true;
                try {
                    if (icase) r.pcre_patterns.emplace_back(pattern, std::regex::ECMAScript | std::regex::icase);
                    else r.pcre_patterns.emplace_back(pattern, std::regex::ECMAScript);
                    r.pcre_mods.push_back(mods);
                } catch (const std::exception &ex) {
                    std::cerr << "Warning: regex compile failed: " << ex.what() << "\n";
                }
            }
        } else if (key == "nocase") {
            if (!r.content_nocase.empty()) r.content_nocase.back() = true;
        } else {
            // ignore other keys for now
        }
    }

    // Only consider rule if it has content or pcre for our matching engine
    return (!r.contents.empty() || !r.pcre_patterns.empty());
}

std::vector<Rule> RuleParser::parse_file(const std::string &path) {
    std::vector<Rule> rules;
    std::ifstream f(path);
    if (!f) {
        std::cerr << "Cannot open rules file: " << path << "\n";
        return rules;
    }
    std::string line;
    int ln = 0;
    while (std::getline(f, line)) {
        ++ln;
        Rule r;
        if (parse_rule_line(line, r)) {
            rules.push_back(std::move(r));
        }
    }
    return rules;
}
