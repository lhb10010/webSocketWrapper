#include </home/pi/webSocketWrapper.h>
#include <string>
#include <regex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstdint>


bool webSocketWrapper::handshake(int clientConnection){

    //get web socket key
    std::string recvString = "";
    

    //can get stuck here. Fix
    while(true){

        char* nextChar = new char;
        recv(clientConnection, nextChar, sizeof(nextChar), 0);
        recvString.append(nextChar);
        
        if(recvString.length() >= 4 && recvString[recvString.length() - 4] == '\r' && recvString[recvString.length() - 3] == '\n' && 
            recvString[recvString.length() - 2] == '\r' && recvString[recvString.length() - 1] == '\n'){

            break;
        }

    }

    std::cout << recvString;

    std::smatch match;
    if(!std::regex_search(recvString, match, std::regex("Sec-WebSocket-Key: .+"))){
        return false;
    }

    std::string websocketKey = match.str(0).substr(19, 24);
    websocketKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    const unsigned char* websocketKeyCStr = reinterpret_cast<const unsigned char*>(websocketKey.c_str());
    unsigned char outputSHA1[20];
    SHA1(websocketKeyCStr, websocketKey.length(), outputSHA1);


    //replace if possible
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, outputSHA1, 20);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    std::string acceptKey(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);


    std::string serverResponse = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
    serverResponse = serverResponse + acceptKey + "\r\n\r\n";

    std::cout << serverResponse;

    send(clientConnection, serverResponse.c_str(), serverResponse.length(), 0);

    return true;

}


char* webSocketWrapper::getNextFrameData(int clientConnection, int& length){

    unsigned char* headerChar = new unsigned char; //ignoring header byte
    recv(clientConnection, headerChar, 1, 0);

    /*
    while(*headerChar != 129){
        std::cout << *headerChar << "\n";
        recv(clientConnection, headerChar, sizeof(headerChar), 0);
    }
    */
    
    unsigned char* maskLengthChar = new unsigned char; 
    recv(clientConnection, maskLengthChar, 1, 0);
    /*
    while(*maskLengthChar != 139){
        std::cout << *maskLengthChar << "\n";
        recv(clientConnection, maskLengthChar, sizeof(maskLengthChar), 0);
    }
    */

    bool mask = false;
    if(*maskLengthChar / 128 == 1){
        mask = true;
        *maskLengthChar -= 128;
    }
    int dataLength = *maskLengthChar;

    unsigned char* maskingKey = new unsigned char[4];
    recv(clientConnection, maskingKey, 4, 0);

    char* outputData = new char[dataLength];
    for(int i = 0; i < dataLength; i++){

        int maskKeyLocation = i % 4;
        unsigned char nextChar[1];
        recv(clientConnection, nextChar, 1, 0);
        outputData[i] = *nextChar ^ maskingKey[maskKeyLocation];
        //std::cout << "i: " << i << " : " << outputData[i] << "\n";

    }
    length = dataLength;
    return outputData;

}


std::string webSocketWrapper::getNextFrameData(int clientConnection){

    int len;
    char* cStr = new char[len + 1];
    char* dataOutput = getNextFrameData(clientConnection, len);
    for(int i = 0; i < len; i++){
        cStr[i] = dataOutput[i];
    }
    cStr[len] = '\0';
    std::string str = cStr;
    return str;

}


bool webSocketWrapper::sendLargeData(unsigned char* data, int length, int clientConnection){

    int headerLength = 0;
    unsigned char header[10];

    if(length > 65535){

        headerLength = 10;
        uint64_t length64 = static_cast<uint64_t>(length);
        unsigned char* length8s = reinterpret_cast<unsigned char*>(&length64);

        for(int i = 0; i < 8; i++){

            header[i + 2] = length8s[7 - i];

        }

        header[1] = 127;

    }
    else{

        headerLength = 4;
        uint16_t length16 = static_cast<uint16_t>(length);
        length16 = htons(length16);
        unsigned char* length8s = reinterpret_cast<unsigned char*>(&length16);
        header[2] = length8s[0];
        header[3] = length8s[1];
        header[1] = 126;

    }

    header[0] = 130;
    
    /*
    std::cout << "len " << length << "\n";
    for(int i = 0; i < 10; i++){

        std::cout << static_cast<int>(header[i]) << "\n";
    }
    */


    send(clientConnection, header, headerLength, 0);
    send(clientConnection, data, length, 0);


    return true;

}