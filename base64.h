#ifndef BASE64_H
#define BASE64_H

#include <string>

// Encoding
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);

// Decoding
std::string base64_decode(std::string const& encoded_string);

#endif // BASE64_H
