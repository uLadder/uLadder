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

enum Socks5AddressingMode
{
    kIpv4 = 1,
    kDomain = 3,
    kIpv6 = 4,
    kAtypeUnknown = 0xFF,
};

enum Socks5Command
{
    kConnect = 1,
    kBind = 2,
    kUdpAssociate = 3,
    kCmdUnknown = 0xFF,
};

struct Socks5Request
{
    Socks5Request()
        : ver_(0xFF), cmd_(0xFF), rsv_(0xFF), atype_(0xFF)
    {}
    uint8_t ver_;
    uint8_t cmd_;
    uint8_t rsv_;
    uint8_t atype_;
    // dst addr
    // dst port
};

enum Socks5ReplyField
{
    kSucceeded = 0,
    kGeneralFailure = 1,
    kConnectionRefusedByRuel = 2,
    kNetworkUnreachable = 3,
    kHostUnreachable = 4,
    kConnectionRefused = 5,
    kTTLExpired = 6,
    kCmdNotSupported = 7,
    kAtypeNotSupported = 8,
    kUndefined = 0xFF
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

    static const uint8_t kSocks5Version = 5;
    static const uint8_t kReservedField = 0;
    static const size_t kMaxTrunk = 16384;
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
    void ReadRequest();
    void ReadDstAddr();
    int ReadRequestDomain();
    void OnRequestReceived();
    void ReplayCmdNotSupport();
    void ReplyAtypeNotSupport();

    void ConnectRemote();
    bool IsRemoteConnected();
    void OnRemoteConnected();

    void ReadPeerData();
    void SendPeerDataToRemote();
    void ReadRemoteDate();
    void SendRemoteDataToPeer();
private:
    Socks5Server& server_;
    Socks5SessionState state_;

    Socks5Request request_;
    uint8_t domain_len_;
    std::string domain_;

    struct sockaddr_in remote_addr_;

    int peer_fd_;
    std::shared_ptr<ev::io> peer_watcher_;
    bool peer_closing_;
    int peer_watch_flag_;

    int remote_fd_;
    std::shared_ptr<ev::io> remote_watcher_;
    bool remote_closing_;
    int remote_watch_flag_;

    ev::default_loop loop_;

    StreamBuffer peer_buffer_;
    StreamBuffer remote_buffer_;
    // IConnection uladder_connection_;
};
