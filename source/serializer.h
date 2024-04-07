#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace Serializer {

auto genCompactInt(const auto &num);
std::string genRaw(const json& data);
std::string getOrigSerialization(const json& data);
std::string getBIP143Serialization(const json& data, unsigned int idx);

}

#endif // SERIALIZER_H