#include <cassert>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "Socks5Session.h"
#include "Socks5Server.h"
#include "easylogging++.h"

Socks5Session::Socks5Session(Socks5Server& server, int peer_fd) :
    server_(server),
    state_(Socks5SessionState::kIdle),
    domain_len_(0),
    domain_(),
    peer_fd_(peer_fd),
    peer_(std::make_shared<ev::io>()),
    peer_closing_(false),
    remote_fd_(-1),
    remote_watcher_(std::make_shared<ev::io>()),
    remote_closing_(false)
{
    memset(&remote_addr_, 0, sizeof(remote_addr_));
    peer_->set<Socks5Session, &Socks5Session::OnPeerEvent>(this);
    peer_->start(peer_fd_, ev::READ);
}

Socks5Session::~Socks5Session()
{
    close(peer_fd_);
    peer_->stop();
}

void Socks5Session::OnPeerEvent(ev::io &watcher, int revents)
{
    if(revents & EV_READ)
    {
        OnPeerCanRead();
    }
    if(revents & EV_WRITE)
    {
        OnPeerCanWrite();
    }
    if(revents & EV_ERROR)
    {
        LOG(INFO) << "fd=" << peer_fd_ << " OnError";
        OnPeerError();
    }
}

void Socks5Session::OnPeerCanRead()
{
    int ret = peer_buffer_.AppendFromSocket(peer_fd_);
    if(ret < 0)
    {
        if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            LOG(INFO) << "Read Error, error=" << strerror(errno);
            peer_closing_ = true;
            state_ = Socks5SessionState::kClosing;
        }
        peer_->set(ev::READ);
    }
    else if(ret == 0)
    {
        LOG(INFO) << "Read Error, peer closed";
        peer_closing_ = true;
        peer_->stop();
        state_ = Socks5SessionState::kClosing;
    }

    switch(state_)
    {
        case Socks5SessionState::kIdle:
            LOG(INFO) << "fd=" << peer_fd_ << " Read Handshaking request";
            state_ = Socks5SessionState::kHandshaking;
            if(peer_buffer_.Size() >= sizeof(Socks5HandshakeRequest))
            {
                OnHandshakeRequest();
            }
            break;
        case Socks5SessionState::kHandshaking:
            ReadRequest();
            break;
        case Socks5SessionState::kEstablished:
        case Socks5SessionState::kClosing:
        default:
            break;
    }
}

void Socks5Session::OnPeerCanWrite()
{
    int ret = remote_buffer_.ExtractToSocket(peer_fd_);

    if(ret <= 0)
    {
        if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            peer_closing_ = true;
            state_ = Socks5SessionState::kClosing;
        }
        peer_->set(ev::WRITE);
    }
    peer_->set(ev::READ);
}

void Socks5Session::OnPeerError()
{
}

void Socks5Session::OnRemoteEvent(ev::io &watcher, int revents)
{
    if(revents & EV_READ)
    {
        OnRemoteCanRead();
    }
    if(revents & EV_WRITE)
    {
        OnRemoteCanWrite();
    }
    if(revents & EV_ERROR)
    {
        LOG(INFO) << "fd=" << peer_fd_ << " OnError";
        OnRemoteError();
    }
}

void Socks5Session::OnRemoteCanRead()
{
    switch(state_)
    {
        case Socks5SessionState::kHandshaking:
            if(IsRemoteConnected())
            {
            }
            else
            {
            }
        case Socks5SessionState::kEstablished:
        case Socks5SessionState::kClosing:
        default:
            assert(0);
    }
}

void Socks5Session::OnRemoteCanWrite()
{
}

void Socks5Session::OnRemoteError()
{
}

void Socks5Session::OnHandshakeRequest()
{
    Socks5HandshakeRequest req;
    peer_buffer_.Extract(&req, sizeof(req));


    Socks5HandshakeReply resp;
    memset(&resp, 0, sizeof(resp));
    resp.ver_ = 5;

    if(req.ver_ != 5)
    {
        LOG(INFO) << "Request version mismatch, req.ver_=" << req.ver_;
        resp.method_ = 0xFF;
    }
    else
    {
        // Currently not support authentication method
        resp.method_ = 0x00;
    }

    LOG(INFO) << "HandShake Done";
    remote_buffer_.Append(&resp, sizeof(resp));
    peer_->set(ev::WRITE);
}

void Socks5Session::ReadRequest()
{
    LOG(INFO) << __func__;
    if(request_.atype_ == Socks5AddressingMode::kAtypeUnknown)
    {
        if(peer_buffer_.Size() < sizeof(Socks5HandshakeRequest))
        {
            return;
        }

        peer_buffer_.Extract(&request_, sizeof(request_));
    }
    else
    {
        if(request_.atype_ == Socks5AddressingMode::kDomain)
        {
            if(ReadRequestDomain() != -1)
            {
                OnRequestReceived();
            }
        }
        else if(request_.atype_ == Socks5AddressingMode::kIpv4)
        {

            LOG(INFO) << "IPV4 is not supported";
            assert(0);
        }
        else if(request_.atype_ == Socks5AddressingMode::kIpv6)
        {
            LOG(INFO) << "IPV6 is not supported";
            assert(0);
        }
    }
}

int Socks5Session::ReadRequestDomain()
{
    LOG(INFO) << __func__;
    if(domain_len_ == 0)
    {
        if(peer_buffer_.Size() < sizeof(domain_len_))
        {
            return -1;
        }
        // Process Domain Len
        peer_buffer_.Extract(&domain_len_, sizeof(domain_len_));
        LOG(INFO) << "DOMAIN len="  << domain_len_;
    }
    else
    {
        if(peer_buffer_.Size() < (size_t)(domain_len_ + 2))
        {
            return -1;
        }
        // Process Domain
        peer_buffer_.Extract(domain_, domain_len_);

        // Read port
        peer_buffer_.Extract(&remote_addr_.sin_port, 2);

        // TODO: Use Async DNS
        struct hostent* ret = gethostbyname(std::string(domain_.c_str(), domain_len_).c_str());
        assert(ret != nullptr);
        memcpy(&remote_addr_.sin_addr.s_addr, ret->h_addr_list[0], 4);

        LOG(INFO) << "DOMAIN = " << domain_ << ", ADDRESS = " << inet_ntoa(remote_addr_.sin_addr) << ":" << ntohs(remote_addr_.sin_port);
    }
    return 0;
}

void Socks5Session::OnRequestReceived()
{
    LOG(INFO) << __func__;
    if(request_.ver_ != kSocks5Version)
    {
    }

    switch(request_.cmd_)
    {
        case Socks5Command::kConnect:
            ConnectRemote();
            return;
        case Socks5Command::kBind:
            LOG(FATAL) << "SOCKS5 BIND NOT SUPPORTED";
        case Socks5Command::kUdpAssociate:
            LOG(FATAL) << "SOCKS5 UDP ASSOCIATE NOT SUPPORTED";
        default:
            LOG(FATAL) << "Unexpected request cmd, cmd=" << request_.cmd_;
            return ReplayCmdNotSupport();
    }

    switch(request_.atype_)
    {
        case Socks5AddressingMode::kDomain:
            break;
        case Socks5AddressingMode::kIpv4:
        case Socks5AddressingMode::kIpv6:
        default:
            return ReplyAtypeNotSupport();
    }
}

void Socks5Session::ReplayCmdNotSupport()
{
    Socks5Reply resp;
    resp.ver_ = kSocks5Version;
    resp.rep_ = Socks5ReplyField::kCmdNotSupported;
    resp.rsv_ = kReservedField;
    resp.atype_ = request_.atype_;
    remote_buffer_.Append(&resp, sizeof(resp));

    // TODO: not only domain is supported
    remote_buffer_.AppendBYTE(domain_.size());
    remote_buffer_.Append(domain_);
    remote_buffer_.AppendWORD(remote_addr_.sin_port);
}

void Socks5Session::ReplyAtypeNotSupport()
{
    Socks5Reply resp;
    resp.ver_ = kSocks5Version;
    resp.rep_ = Socks5ReplyField::kAtypeNotSupported;
    resp.rsv_ = kReservedField;
    resp.atype_ = request_.atype_;
    remote_buffer_.Append(&resp, sizeof(resp));

    // TODO: not only domain is supported
    remote_buffer_.AppendBYTE(domain_.size());
    remote_buffer_.Append(domain_);
    remote_buffer_.AppendWORD(remote_addr_.sin_port);
}

void Socks5Session::ConnectRemote()
{
    LOG(INFO) << __func__;
    remote_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    fcntl(remote_fd_, F_SETFL, fcntl(remote_fd_, F_GETFL) | O_NONBLOCK);
    connect(remote_fd_, (struct sockaddr*)&remote_addr_, sizeof(remote_addr_));

    remote_watcher_->set<Socks5Session, &Socks5Session::OnRemoteEvent>(this);
    remote_watcher_->start(remote_fd_, ev::READ);
}

bool Socks5Session::IsRemoteConnected()
{
    char c;
    int rv = recv(remote_fd_, &c, 1, MSG_PEEK);
    if(rv == 0)
    {
        DVLOG(0) << __func__ << " rv=0, errno=" << errno << " fd=" << remote_fd_;
        return false;
    }
    if(rv == -1 && errno != EAGAIN)
    {
        DVLOG(0) << __func__ << " rv=-1, errno=" << errno << " (" << strerror(errno) << " ) fd=" << remote_fd_;
        return false;
    }
    return true;
}

void Socks5Session::OnRemoteConnected()
{
    LOG(INFO) << __func__;
    Socks5Reply resp;
    memset(&resp, 0, sizeof(resp));

    resp.ver_ = 5;
    resp.rep_ = 0;
    resp.rsv_ = 0;
    resp.atype_ = 1;

    remote_buffer_.Append(&resp, sizeof(resp));
    remote_buffer_.Append(&remote_addr_.sin_addr.s_addr, 4);
    remote_buffer_.Append(&remote_addr_.sin_port, 2);

    state_ = Socks5SessionState::kEstablished;
    peer_->set(ev::WRITE);
}
