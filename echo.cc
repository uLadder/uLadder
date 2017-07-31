#include <iostream>
#include <functional>
#include <cassert>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ev++.h>

#include "echo.h"


Socks5Server::Socks5Server()
{
    listen_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9981);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr));
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
    loop_.run();
}

void Socks5Server::OnConnectRequest()
{
    std::cout << "New Connection in!" << std::endl;
    struct sockaddr peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    int peerfd = accept(listen_fd_, &peer_addr, &peer_len);
    assert(peerfd > 0);

    ev::io* pio = new ev::io();
    io_watchers_[peerfd] = pio;

    pio->set<Socks5Server, &Socks5Server::OnEvent>(this);
    pio->start(peerfd, ev::READ);
}


void Socks5Server::OnEvent(ev::io &watcher, int revents)
{
    if(revents & EV_READ)
    {
        OnCanRead(watcher.fd);
    }
    if(revents & EV_WRITE)
    {
        OnCanWrite(watcher.fd);
    }
    if(revents & EV_ERROR)
    {
        OnError(watcher.fd);
    }
}

void Socks5Server::OnCanRead(int fd)
{
    std::cout << "Read event on fd=" << fd << std::endl;
    if(buffers_.find(fd) == buffers_.end())
    {
        buffers_[fd] = "";
    }

    char buf[1024] = { 0 };
    int nread = read(fd, buf, 1024);
    if(nread == 0)
    {
        OnClose(fd);
    }
    else
    {
        buffers_[fd] += std::string(buf, nread);
        io_watchers_[fd]->set(ev::WRITE);
    }
}

void Socks5Server::OnCanWrite(int fd)
{
    std::cout << "Write event on fd=" << fd << std::endl;
    int nwrite = write(fd, buffers_[fd].c_str(), buffers_[fd].size());
    buffers_[fd].erase(0, nwrite);
    io_watchers_[fd]->set(ev::READ);
}

void Socks5Server::OnError(int fd)
{
    std::cout << "Error event on fd=" << fd << std::endl;
    assert(0);
}

void Socks5Server::OnClose(int fd)
{
    std::cout << "Connection dropped on fd=" << fd << std::endl;
    buffers_.erase(fd);
    io_watchers_[fd]->stop();
    io_watchers_.erase(fd);

    close(fd);
}
