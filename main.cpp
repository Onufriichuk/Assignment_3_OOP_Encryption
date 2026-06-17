#include <iostream>
#include <string>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <dlfcn.h>
#endif

typedef void cipher_t;

typedef cipher_t* (*CreateCaesarFunc)(int);
typedef cipher_t* (*CreateVigenereFunc)(const char*);
typedef char* (*EncryptFunc)(cipher_t*, const char*);
typedef char* (*DecryptFunc)(cipher_t*, const char*);
typedef void (*DestroyFunc)(cipher_t*);
typedef void (*FreeFunc)(char*);

#ifdef _WIN32
void* loadSymbol(HMODULE library, const char* name) {
    return reinterpret_cast<void*>(GetProcAddress(library, name));
}
#else
void* loadSymbol(void* library, const char* name) {
    return dlsym(library, name);
}
#endif

int main() {
#ifdef _WIN32
    HMODULE library = LoadLibraryA("cipher.dll");
#else
    void* library = dlopen("./libcipher.dylib", RTLD_LAZY);

    if (!library) {
        library = dlopen("./libcipher.so", RTLD_LAZY);
    }
#endif

    if (!library) {
        std::cerr << "Error: cannot load cipher library." << std::endl;
        return 1;
    }

    auto createCaesar = reinterpret_cast<CreateCaesarFunc>(
        loadSymbol(library, "cipher_create_caesar")
    );

    auto createVigenere = reinterpret_cast<CreateVigenereFunc>(
        loadSymbol(library, "cipher_create_vigenere")
    );

    auto encrypt = reinterpret_cast<EncryptFunc>(
        loadSymbol(library, "cipher_encrypt")
    );

    auto decrypt = reinterpret_cast<DecryptFunc>(
        loadSymbol(library, "cipher_decrypt")
    );

    auto destroy = reinterpret_cast<DestroyFunc>(
        loadSymbol(library, "cipher_destroy")
    );

    auto freeResult = reinterpret_cast<FreeFunc>(
        loadSymbol(library, "cipher_free")
    );

    if (!createCaesar || !createVigenere || !encrypt || !decrypt || !destroy || !freeResult) {
        std::cerr << "Error: cannot resolve all library functions." << std::endl;

#ifdef _WIN32
        FreeLibrary(library);
#else
        dlclose(library);
#endif

        return 1;
    }

    std::cout << "Choose cipher:" << std::endl;
    std::cout << "1 - Caesar" << std::endl;
    std::cout << "2 - Vigenere" << std::endl;
    std::cout << "Your choice: ";

    int cipherChoice;
    std::cin >> cipherChoice;
    std::cin.ignore();

    cipher_t* cipher = nullptr;

    if (cipherChoice == 1) {
        int key;
        std::cout << "Enter Caesar key: ";
        std::cin >> key;
        std::cin.ignore();

        cipher = createCaesar(key);
    } else if (cipherChoice == 2) {
        std::string key;
        std::cout << "Enter Vigenere key: ";
        std::getline(std::cin, key);

        cipher = createVigenere(key.c_str());
    } else {
        std::cerr << "Invalid cipher choice." << std::endl;

#ifdef _WIN32
        FreeLibrary(library);
#else
        dlclose(library);
#endif

        return 1;
    }

    if (!cipher) {
        std::cerr << "Error: cannot create cipher." << std::endl;

#ifdef _WIN32
        FreeLibrary(library);
#else
        dlclose(library);
#endif

        return 1;
    }

    std::cout << "Choose operation:" << std::endl;
    std::cout << "1 - Encrypt" << std::endl;
    std::cout << "2 - Decrypt" << std::endl;
    std::cout << "Your choice: ";

    int operationChoice;
    std::cin >> operationChoice;
    std::cin.ignore();

    std::string text;
    std::cout << "Enter text: ";
    std::getline(std::cin, text);

    char* result = nullptr;

    if (operationChoice == 1) {
        result = encrypt(cipher, text.c_str());
    } else if (operationChoice == 2) {
        result = decrypt(cipher, text.c_str());
    } else {
        std::cerr << "Invalid operation choice." << std::endl;
        destroy(cipher);

#ifdef _WIN32
        FreeLibrary(library);
#else
        dlclose(library);
#endif

        return 1;
    }

    if (!result) {
        std::cerr << "Error: operation failed." << std::endl;
        destroy(cipher);

#ifdef _WIN32
        FreeLibrary(library);
#else
        dlclose(library);
#endif

        return 1;
    }

    std::cout << "Result: " << result << std::endl;

    freeResult(result);
    destroy(cipher);

#ifdef _WIN32
    FreeLibrary(library);
#else
    dlclose(library);
#endif

    return 0;
}