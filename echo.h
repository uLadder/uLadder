#include <cstdint>
#include <ev++.h>
#include <unordered_map>

struct Socks5HandshakeRequest
{
    uint8_t ver_;
    uint8_t nmethods_;
    uint8_t methods_;
};

struct Socks5HandshakeReply
{
    uint8_t ver_;
    uint8_t methods_;
};

struct Sock5Request
{
    uint8_t ver_;
    uint8_t cmd_;
    uint8_t rsv_;
    uint8_t atype_;
    uint8_t dst_addr_[16];
    uint16_t dst_port_;
};

struct Socks5Reply
{
    uint8_t ver_;
    uint8_t rep_;
    uint8_t rsv_;
    uint8_t atype_;
    uint8_t bnd_addr_[16];
    uint16_t bnd_port_;
};


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
    void OnEvent(ev::io &watcher, int revents);
    void OnCanRead(int fd);
    void OnCanWrite(int fd);
    void OnError(int fd);
    void OnClose(int fd);
private:
    std::unordered_map<int, ev::io*> io_watchers_;
    std::unordered_map<int, std::string> buffers_;
    int listen_fd_;
    ev::io io_;
    ev::default_loop loop_;
};
