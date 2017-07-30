#include <vector>

class StreamBuffer
{
    static const size_t kInitSize = 1024;
public:
    StreamBuffer();
    ~StreamBuffer();
    int Append(void* buf, size_t len);
    int Extract(void* buf, size_t len);
    int AppendFromSocket(int fd);
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
