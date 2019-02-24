#include <stdint.h>
#include <stdio.h>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <iomanip> // std::setw
#include <thread>
#include <chrono>
using namespace std;

#if !defined(HETOBE16)
#if !defined(__BYTE_ORDER)
#error Failed to detect byte order!
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
#define HETOBE64(x) (x)
#define HETOLE64(x) __bswap_constant_64(x)
#define HETOBE32(x) (x)
#define HETOLE32(x) __bswap_constant_32(x)
#define HETOBE16(x) (x)
#define HETOLE16(x) __bswap_constant_16(x)
//
#define LETOHE64(x) __bswap_constant_64(x)
#define BETOHE64(x) (x)
#define LETOHE32(x) __bswap_constant_32(x)
#define BETOHE32(x) (x)
#define LETOHE16(x) __bswap_constant_16(x)
#define BETOHE16(x) (x)
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HETOBE64(x) __bswap_constant_64(x)
#define HETOLE64(x) (x)
#define HETOBE32(x) __bswap_constant_32(x)
#define HETOLE32(x) (x)
#define HETOBE16(x) __bswap_constant_16(x)
#define HETOLE16(x) (x)
//
#define LETOHE64(x) (x)
#define BETOHE64(x) __bswap_constant_64(x)
#define LETOHE32(x) (x)
#define BETOHE32(x) __bswap_constant_32(x)
#define LETOHE16(x) (x)
#define BETOHE16(x) __bswap_constant_16(x)
#else
#error Failed to detect byte order! appears to be neither big endian nor little endian..
#endif
#endif
#endif

static std::string dump_string(const std::string &input)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (std::string::const_iterator i = input.begin(), n = input.end(); i != n; ++i)
    {
        std::string::value_type c = (*i);

        // Keep alphanumeric and other accepted characters intact
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == ',' || c == '~' || c == ' ' || c == '	' || c == '!' || c == ':' || c == ';')
        {
            escaped << c;
            continue;
        }
        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char)c);
        escaped << std::nouppercase;
    }
    return ("string(" + std::to_string(input.length()) + "): \"" + escaped.str() + "\"");
}

static void sendMessage(const string &message)
{
    uint16_t size = message.size();
    size = HETOLE16(size);
    cout.write((char *)&size, sizeof(size));
    cout << message << flush;
}

static string readMessage(void)
{
    if (!cin.good())
    {
        exit(EXIT_FAILURE);
    }
    uint16_t size;
    cin.read((char *)&size, sizeof(size));
    if (!cin.good())
    {
        exit(EXIT_FAILURE);
    }
    size = LETOHE16(size);
    if (!size)
    {
        return "";
    }
    string ret(size, '\0');
    cin.read(&ret[0], size);
    if (!cin.good())
    {
        exit(EXIT_FAILURE);
    }
    return ret;
}

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */

static void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
{
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (i = 0; i < num_rounds; i++)
    {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

static void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4])
{
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
    for (i = 0; i < num_rounds; i++)
    {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}
int main(int argc, char *argv[])
{
    uint32_t keys[4];
    // init
    {
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        string firstMessage = readMessage();
        if (firstMessage.length() != (4 * 4))
        {
            cerr << "ERROR: FIRST MESSAGE WAS NOT EXACTLY 4*4 bytes! (the XTEA keys) - was: " << dump_string(firstMessage) << endl;
            exit(EXIT_FAILURE);
        }
        for (size_t i = 0; i < 4; ++i)
        {
            keys[i] = LETOHE32(*((uint32_t *)(&firstMessage[i * 4])));
            //cerr << "keys[" << i << "]: " << keys[i] << endl;
        }
    }
    //std::this_thread::sleep_for(std::chrono::seconds(9));
    for (;;)
    {
        string message = readMessage();
        uint8_t header = uint8_t(message[0]);
        if (header == 0)
        {
            // encrypt
            message.erase(0, 3); // u8 message header and u16 length header..
            //cerr << "TO ENCRYPT: " << dump_string(message) << endl;
            for (size_t i = 0; i < message.length(); i += 8)
            {
                encipher(32, (uint32_t *)&message[i], keys);
            }
            //cerr << "ENCRYPTED: " << dump_string(message) << endl;
            sendMessage(message);
        }
        else if (header == 1)
        {
            // decrypt
            message.erase(0, 3); // u8 message header and u16 length header..
            //cerr << "TO DECRYPT: " << dump_string(message) << endl;
            for (size_t i = 0; i < message.length(); i += 8)
            {
                decipher(32, (uint32_t *)&message[i], keys);
            }
            //cerr << "DECRYPTED: " << dump_string(message) << endl;
            sendMessage(message);
        }
        else
        {
            std::runtime_error("invalid message header! " + dump_string(message));
        }
    }
};
