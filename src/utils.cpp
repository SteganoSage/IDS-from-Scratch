#include "Utils.hpp"
#include <cctype>

std::string trim(const std::string &s) {
    size_t a = 0; while (a < s.size() && std::isspace((unsigned char)s[a])) ++a;
    size_t b = s.size(); while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b - a);
}

bool parse_quoted(const std::string &s, size_t &pos, std::string &out) {
    out.clear();
    if (pos >= s.size() || s[pos] != '"') return false;
    ++pos;
    while (pos < s.size()) {
        char c = s[pos++];
        if (c == '\\') {
            if (pos >= s.size()) break;
            char e = s[pos++];
            if (e == 'n') out.push_back('\n');
            else if (e == 'r') out.push_back('\r');
            else if (e == 't') out.push_back('\t');
            else out.push_back(e);
        } else if (c == '"') {
            return true;
        } else {
            out.push_back(c);
        }
    }
    return false;
}

bool parse_pcre(const std::string &s, size_t &pos, std::string &out, std::string &mods) {
    out.clear(); mods.clear();
    if (pos >= s.size() || s[pos] != '"') return false;
    ++pos;
    if (pos >= s.size()) return false;
    char delim = s[pos++]; // e.g. '/'
    std::string body;
    while (pos < s.size()) {
        char c = s[pos++];
        if (c == '\\') {
            if (pos < s.size()) {
                body.push_back('\\');
                body.push_back(s[pos++]);
            } else return false;
        } else if (c == delim) {
            size_t opts_start = pos;
            while (pos < s.size() && s[pos] != '"') ++pos;
            if (pos >= s.size()) return false;
            mods = s.substr(opts_start, pos - opts_start);
            ++pos; // skip closing quote
            out = body;
            return true;
        } else {
            body.push_back(c);
        }
    }
    return false;
}

std::string unescape_snort_string(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char next = s[i+1];
            if (next == 'n') { out.push_back('\n'); i += 2; }
            else if (next == 'r') { out.push_back('\r'); i += 2; }
            else if (next == 't') { out.push_back('\t'); i += 2; }
            else { out.push_back(next); i += 2; }
        } else {
            out.push_back(s[i++]);
        }
    }
    return out;
}
