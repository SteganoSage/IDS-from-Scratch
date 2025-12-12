#include "Rule_Matcher.hpp"
#include <algorithm>
#include <cctype>

static std::string to_lower(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) out.push_back(std::tolower(c));
    return out;
}

bool RuleMatcher::matches(const Rule &r, const std::string &payload) {
    // all contents must match (AND), all pcre must match (AND) — simple semantics
    for (size_t i = 0; i < r.contents.size(); ++i) {
        const std::string &c = r.contents[i];
        bool nocase = (i < r.content_nocase.size()) ? r.content_nocase[i] : false;
        if (c.empty()) continue;
        if (!nocase) {
            if (payload.find(c) == std::string::npos) return false;
        } else {
            if (to_lower(payload).find(to_lower(c)) == std::string::npos) return false;
        }
    }
    for (const auto &re : r.pcre_patterns) {
        try {
            if (!std::regex_search(payload, re)) return false;
        } catch (...) {
            return false;
        }
    }
    return true;
}
