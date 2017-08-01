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
    size_(0),
    read_index_(0),
    write_index_(0)
{
}

StreamBuffer::~StreamBuffer()
{
    free(buffer_);
}

int StreamBuffer::Append(const void* buf, size_t len)
{
    EnsureCapacity(len);
    memcpy(buffer_ + write_index_, buf, len);
    write_index_ += len;
    size_ += len;
    capacity_ -= len;
    return len;
}

int StreamBuffer::Append(const std::string& buf)
{
    return Append(buf.c_str(), buf.size());
}

int StreamBuffer::AppendBYTE(uint8_t byte)
{
    return Append(&byte, sizeof(byte));
}

int StreamBuffer::AppendWORD(uint16_t word)
{
    return Append(&word, sizeof(word));
}

int StreamBuffer::AppendDWORD(uint32_t dword)
{
    return Append(&dword, sizeof(dword));
}

int StreamBuffer::AppendQWORD(uint64_t qword)
{
    return Append(&qword, sizeof(qword));
}

int StreamBuffer::Extract(void* buf, size_t len)
{
    memcpy(buf, buffer_ + read_index_, len);
    size_ -= len;
    read_index_ += len;
    return len;
}

int StreamBuffer::Extract(std::string& buf, size_t len)
{
    void* tmp = malloc(len);
    int ret = Extract(tmp, len);
    buf = std::string((char*)tmp, len);
    free(tmp);
    return ret;
}

int StreamBuffer::AppendFromSocket(int fd)
{
    // LOG(INFO) << __func__ << ", fd=" << fd;
    int totalread = 0;
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
            nread = read(fd, buffer_ + write_index_, leftspace);
            if(nread > 0)
            {
                totalread += nread;
                write_index_ += nread;
                size_ = write_index_ - read_index_;
            }
        }
    }
    LOG(INFO) << __func__ << ", fd=" << fd << ", totalread=" << totalread << ", ret=" << nread;
    return nread;
}

int StreamBuffer::AppendFromSocket(int fd, size_t limit)
{
    EnsureCapacity(limit);
    int totalread = 0;
    int nread = 1;
    while(nread > 0 && limit > 0)
    {
        nread = read(fd, buffer_ + write_index_, limit);
        if(nread > 0)
        {
            limit -= nread;
            totalread += nread;
            write_index_ += nread;
            size_ = write_index_ - read_index_;
        }
    }
    LOG(INFO) << __func__ << ", fd=" << fd << ", totalread=" << totalread << ", ret=" << nread;
    return nread;
}

int StreamBuffer::ExtractToSocket(int fd)
{
    int totalwrite = 0;
    int nwrite = 1;
    while(nwrite > 0 && size_ > 0)
    {
        nwrite = write(fd, buffer_ + read_index_, size_);
        if(nwrite > 0)
        {
            totalwrite += nwrite;
            read_index_ += nwrite;
            size_ = write_index_ - read_index_;
        }
    }

    LOG(INFO) << __func__ << ", fd=" << fd << ", totalwrite=" << totalwrite<< ", ret=" << nwrite;
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
