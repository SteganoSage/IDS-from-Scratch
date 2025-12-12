#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>

// trim both ends
std::string trim(const std::string &s);

// parse a quoted string starting at s[pos] == '"'
// advances pos to character after the closing quote if successful
// returns true on success and places unescaped content into out
bool parse_quoted(const std::string &s, size_t &pos, std::string &out);

// parse pcre like: " /.../mods " (pos at opening '"')
// returns regex body (without delimiters) in out and modifiers (e.g., "i") in mods
bool parse_pcre(const std::string &s, size_t &pos, std::string &out, std::string &mods);

// unescape snort-like escapes in a string (e.g. \n, \", \\)
std::string unescape_snort_string(const std::string &s);

#endif // UTILS_HPP
