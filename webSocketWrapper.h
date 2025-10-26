#include <string>


class webSocketWrapper{

    public:
        bool handshake(int clientConnection);
        char* getNextFrameData(int clientConnection, int& length);
        bool sendLargeData(unsigned char* data, int length, int clientConnection);
        std::string getNextFrameData(int clientConnection);

    private:


};