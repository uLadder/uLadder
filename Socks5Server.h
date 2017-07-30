#include <cstdint>
#include <memory>
#include <ev++.h>
#include <unordered_map>
#include <unordered_set>
#include <netinet/in.h>

class Socks5Session;

class TcpConnection
{
};

class Socks5Server
{
public:
    Socks5Server();
    ~Socks5Server();

    void Run();
    void OnConnectRequest();
    void OnSessionDestroy(int peerfd);
private:
    std::unordered_map<int, std::shared_ptr<Socks5Session>> sessions_;

    int listen_fd_;

    struct sockaddr_in listen_addr_;

    ev::io io_;
    ev::default_loop loop_;
};
