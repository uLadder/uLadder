#include <string>

class StreamBuffer
{
    static const size_t kInitSize = 102400;
public:
    StreamBuffer();
    ~StreamBuffer();
    int Append(const void* buf, size_t len);
    int Append(const std::string& buf);
    int AppendBYTE(uint8_t byte);
    int AppendWORD(uint16_t word);
    int AppendDWORD(uint32_t word);
    int AppendQWORD(uint64_t word);

    int Extract(void* buf, size_t len);
    int Extract(std::string& buf, size_t len);

    int AppendFromSocket(int fd);
    int AppendFromSocket(int fd, size_t limit);
    int ExtractToSocket(int fd);
    size_t Size();
private:
    void EnsureCapacity(size_t len);
    void Expand(size_t len);
    void Shrink();
private:
    char* buffer_;
    size_t capacity_;
    size_t size_;
    size_t read_index_;
    size_t write_index_;
};
