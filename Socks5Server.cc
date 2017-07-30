#include <iostream>
#include <functional>
#include <cassert>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ev++.h>
#include "easylogging++.h"

#include "Socks5Server.h"
#include "Socks5Session.h"


Socks5Server::Socks5Server()
{
    listen_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    int enabled = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(int));

    listen_addr_.sin_family = AF_INET;
    listen_addr_.sin_port = htons(9981);
    listen_addr_.sin_addr.s_addr = INADDR_ANY;


    bind(listen_fd_, (struct sockaddr*)&listen_addr_, sizeof(listen_addr_));
    listen(listen_fd_, 1024);

    io_.set<Socks5Server, &Socks5Server::OnConnectRequest>(this);
    io_.start(listen_fd_, ev::READ);
}

Socks5Server::~Socks5Server()
{
    close(listen_fd_);
}

void Socks5Server::Run()
{
    LOG(INFO) << "Socks5Server Started...";
    LOG(INFO) << "Listen on " << inet_ntoa(listen_addr_.sin_addr) << ":" << ntohs(listen_addr_.sin_port);
    loop_.run();
}

void Socks5Server::OnConnectRequest()
{
    std::cout << "New Connection in!" << std::endl;
    struct sockaddr peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    int peerfd = accept(listen_fd_, &peer_addr, &peer_len);
    assert(peerfd > 0);

    int ret = fcntl(peerfd, F_SETFL, (fcntl(peerfd, F_GETFL) | O_NONBLOCK));
    assert(ret == 0);
    std::shared_ptr<Socks5Session> session = std::make_shared<Socks5Session>(*this, peerfd);
    sessions_[peerfd] = session;
}

void Socks5Server::OnSessionDestroy(int peerfd)
{
    sessions_.erase(peerfd);
}
