#include <ev++.h>
#include <memory>
#include "StreamBuffer.h"

class Socks5Server;

struct Socks5HandshakeRequest
{
    uint8_t ver_;
    uint8_t nmethods_;
    uint8_t methods_;
};

struct Socks5HandshakeReply
{
    uint8_t ver_;
    uint8_t method_;
};

struct Socks5Request
{
    uint8_t ver_;
    uint8_t cmd_;
    uint8_t rsv_;
    uint8_t atype_;
    // dst addr
    // dst port
};

struct Socks5Reply
{
    uint8_t ver_;
    uint8_t rep_;
    uint8_t rsv_;
    uint8_t atype_;
    // bnd addr
    // bnd port
};

class Socks5Session
{
    enum Socks5SessionState
    {
        kIdle,
        kHandshaking,
        kEstablished,
        kClosing,
    };

    enum Socks5AddressingMode
    {
        kUnknown,
        kIpv4,
        kIpv6,
        kDomain,
    };

    enum Socks5Command
    {
        kConnect = 1,
        kBind = 2,
        kUdpAssociate = 3,
    };

    public:
        Socks5Session(Socks5Server& server, int peer_fd);
        ~Socks5Session();

        void OnPeerEvent(ev::io &watcher, int revents);
        void OnPeerCanRead();
        void OnPeerCanWrite();
        void OnPeerError();

        void OnRemoteEvent(ev::io &watcher, int revents);
        void OnRemoteCanRead();
        void OnRemoteCanWrite();
        void OnRemoteError();
    private:
        void OnHandshakeRequest();
        void OnRequest();
        void ProcessRequest();

        void ConnectRemote();
        bool IsRemoteConnected();
        void OnRemoteConnected();
    private:
        Socks5Server& server_;
        Socks5SessionState state_;
        Socks5AddressingMode atype_;

        Socks5Request request_;
        uint8_t domain_len_;
        void* domain_;

        struct sockaddr_in remote_addr_;

        int peer_fd_;
        std::shared_ptr<ev::io> peer_;
        bool peer_closing_;

        int remote_fd_;
        std::shared_ptr<ev::io> remote_watcher_;
        bool remote_closing_;

        ev::default_loop loop_;

        StreamBuffer peer_buffer_;
        StreamBuffer remote_buffer_;
        // IConnection uladder_connection_;
};
