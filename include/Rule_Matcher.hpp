#ifndef RULEMATCHER_HPP
#define RULEMATCHER_HPP

#include "Rules.hpp"
#include <string>

class RuleMatcher {
public:
    // returns true if rule matches payload
    static bool matches(const Rule &r, const std::string &payload);
};

#endif // RULEMATCHER_HPP
