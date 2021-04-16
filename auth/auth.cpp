
#include "../main.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "json.h"
using json = nlohmann::json;

int v::auth::authenticate(std::string hwid, std::string token)
{
    char path[MAX_PATH];
    GetModuleFileName(0, path, MAX_PATH);

    std::ifstream file(path, std::ios::binary | std::ios::in | std::ios::ate);
    uint64_t uid = 0;
    if (file.is_open() && file.good()) {

        size_t size = file.tellg();
        char* memblock = new char[size];
        file.seekg(0, std::ios::beg);
        file.read(memblock, size);
        file.close();

        uint8_t out[8];

        unsigned int pos = 0;
        for (unsigned int i = size - 8; i < size; i++) {

            out[pos] = (uint8_t)memblock[i];
            pos++;
        }
        delete[] memblock;

        const auto u8tou64 = [](uint8_t const u8[8]) {

            uint64_t u64;
            memcpy(&u64, u8, sizeof u64);
            return u64;
        };

        uid = u8tou64(out);
    }
    return v::auth::authenticated;
}