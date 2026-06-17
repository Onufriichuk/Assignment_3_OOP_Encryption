#include "cipher_api.h"

#include <string>
#include <cstring>
#include <cctype>
#include <stdexcept>

class Cipher {
public:
    virtual std::string encrypt(const std::string& text) = 0;
    virtual std::string decrypt(const std::string& text) = 0;
    virtual ~Cipher() = default;
};

class CaesarCipher : public Cipher {
private:
    int key_;

    char shiftChar(char ch, int shift) const {
        if (!std::isalpha(static_cast<unsigned char>(ch))) {
            return ch;
        }

        char base = std::isupper(static_cast<unsigned char>(ch)) ? 'A' : 'a';
        int position = ch - base;
        int newPosition = (position + shift) % 26;

        if (newPosition < 0) {
            newPosition += 26;
        }

        return static_cast<char>(base + newPosition);
    }

public:
    explicit CaesarCipher(int key) : key_(key % 26) {}

    std::string encrypt(const std::string& text) override {
        std::string result;

        for (char ch : text) {
            result += shiftChar(ch, key_);
        }

        return result;
    }

    std::string decrypt(const std::string& text) override {
        std::string result;

        for (char ch : text) {
            result += shiftChar(ch, -key_);
        }

        return result;
    }
};

class VigenereCipher : public Cipher {
private:
    std::string key_;

    char shiftChar(char ch, int shift) const {
        if (!std::isalpha(static_cast<unsigned char>(ch))) {
            return ch;
        }

        char base = std::isupper(static_cast<unsigned char>(ch)) ? 'A' : 'a';
        int position = ch - base;
        int newPosition = (position + shift) % 26;

        if (newPosition < 0) {
            newPosition += 26;
        }

        return static_cast<char>(base + newPosition);
    }

    int keyShift(size_t index) const {
        char keyChar = key_[index % key_.size()];
        return std::toupper(static_cast<unsigned char>(keyChar)) - 'A';
    }

public:
    explicit VigenereCipher(const std::string& key) {
        for (char ch : key) {
            if (std::isalpha(static_cast<unsigned char>(ch))) {
                key_ += ch;
            }
        }

        if (key_.empty()) {
            throw std::invalid_argument("Vigenere key must contain letters");
        }
    }

    std::string encrypt(const std::string& text) override {
        std::string result;
        size_t keyIndex = 0;

        for (char ch : text) {
            if (std::isalpha(static_cast<unsigned char>(ch))) {
                result += shiftChar(ch, keyShift(keyIndex));
                keyIndex++;
            } else {
                result += ch;
            }
        }

        return result;
    }

    std::string decrypt(const std::string& text) override {
        std::string result;
        size_t keyIndex = 0;

        for (char ch : text) {
            if (std::isalpha(static_cast<unsigned char>(ch))) {
                result += shiftChar(ch, -keyShift(keyIndex));
                keyIndex++;
            } else {
                result += ch;
            }
        }

        return result;
    }
};

static char* copyString(const std::string& str) {
    char* result = new char[str.size() + 1];
    std::strcpy(result, str.c_str());
    return result;
}

extern "C" {

EXPORT cipher_t* cipher_create_caesar(int key) {
    try {
        return reinterpret_cast<cipher_t*>(new CaesarCipher(key));
    } catch (...) {
        return nullptr;
    }
}

EXPORT cipher_t* cipher_create_vigenere(const char* key) {
    try {
        if (key == nullptr) {
            return nullptr;
        }

        return reinterpret_cast<cipher_t*>(new VigenereCipher(key));
    } catch (...) {
        return nullptr;
    }
}

EXPORT char* cipher_encrypt(cipher_t* cipher, const char* text) {
    try {
        if (cipher == nullptr || text == nullptr) {
            return nullptr;
        }

        Cipher* realCipher = reinterpret_cast<Cipher*>(cipher);
        std::string result = realCipher->encrypt(text);
        return copyString(result);
    } catch (...) {
        return nullptr;
    }
}

EXPORT char* cipher_decrypt(cipher_t* cipher, const char* text) {
    try {
        if (cipher == nullptr || text == nullptr) {
            return nullptr;
        }

        Cipher* realCipher = reinterpret_cast<Cipher*>(cipher);
        std::string result = realCipher->decrypt(text);
        return copyString(result);
    } catch (...) {
        return nullptr;
    }
}

EXPORT void cipher_destroy(cipher_t* cipher) {
    Cipher* realCipher = reinterpret_cast<Cipher*>(cipher);
    delete realCipher;
}

EXPORT void cipher_free(char* str) {
    delete[] str;
}

}