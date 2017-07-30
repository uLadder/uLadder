#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cassert>
#include <sys/socket.h>
#include "StreamBuffer.h"

#include "easylogging++.h"

StreamBuffer::StreamBuffer() :
    buffer_((char*)malloc(kInitSize)),
    capacity_(kInitSize),
    read_index_(0),
    write_index_(0)
{
}

StreamBuffer::~StreamBuffer()
{
    free(buffer_);
}

int StreamBuffer::Append(void* buf, size_t len)
{
    EnsureCapacity(len);
    memcpy(buffer_ + write_index_, buf, len);
    write_index_ += len;
    size_ += len;
    capacity_ -= len;
    return len;
}

int StreamBuffer::Extract(void* buf, size_t len)
{
    memcpy(buf, buffer_ + read_index_, len);
    size_ -= len;
    read_index_ += len;
    return len;
}

int StreamBuffer::AppendFromSocket(int fd)
{
    int nread = 1;
    int leftspace = 0;
    while(nread > 0)
    {
        leftspace = capacity_ - write_index_;
        if(leftspace < 0)
        {
            assert(0);
        }
        else if(leftspace == 0)
        {
            Expand(size_);
        }
        else
        {
            LOG(INFO) << "StartRead on fd=" << fd;
            nread = read(fd, buffer_ + write_index_, leftspace);
            LOG(INFO) << "fd=" << fd << ", nread=" << nread;
            if(nread > 0)
            {
                write_index_ += nread;
                size_ = write_index_ - read_index_;
            }
        }
    }

    return nread;
}

int StreamBuffer::ExtractToSocket(int fd)
{
    int nwrite = 1;
    while(nwrite > 0 && size_ > 0)
    {
        nwrite = write(fd, buffer_ + read_index_, size_);
        if(nwrite > 0)
        {
            read_index_ += nwrite;
            size_ = write_index_ - read_index_;
        }
    }

    return nwrite;
}

size_t StreamBuffer::Size()
{
    return size_;
}

void StreamBuffer::EnsureCapacity(size_t len)
{
    if(capacity_ <= len)
    {
        Expand(len);
    }
}

void StreamBuffer::Expand(size_t len)
{
    char* newbuf = (char*)malloc(size_ + capacity_ + len);
    memcpy(newbuf, buffer_, size_);
    read_index_ = 0;
    write_index_ = size_;
    capacity_ = capacity_ + len;
}

void StreamBuffer::Shrink()
{
}
