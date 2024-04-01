#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace Serializer {
    
std::vector<uint8_t> getAsVector(const std::string& hex);
std::string getAsString(const std::vector<uint8_t>& bytes);
auto genCompactInt(const auto &num);
std::string genRawFromJson(const json& data);
std::string getForVerificationFromJson(const json& data);

}

#endif // SERIALIZER_H