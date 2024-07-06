#pragma once
#include <vector>
#include <string>

class Words {
public:
    static std::vector<std::string> WordList;
    static std::vector<std::string> EncodedWordList;
    static std::vector<unsigned char> Decode(const std::vector<std::string>& encodedWordList);
};
