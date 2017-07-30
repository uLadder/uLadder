#include "easylogging++.h"
#include "Socks5Server.h"

INITIALIZE_EASYLOGGINGPP

int main()
{
    Socks5Server server;
    server.Run();
    return 0;
}
