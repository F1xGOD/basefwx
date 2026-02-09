#pragma once

#include "basefwx/system_info.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <array>

namespace basefwx::filestream {

// Use stack buffers for efficient streaming - no heap allocations
constexpr std::size_t kDefaultChunkSize = 65536;  // 64KB chunks
constexpr std::size_t kSmallChunkSize = 16384;    // 16KB for limited memory systems
constexpr std::size_t kLargeChunkSize = 262144;   // 256KB for fast systems

// Buffered file reader with stack-allocated chunk buffer
template<std::size_t ChunkSize = kDefaultChunkSize>
class BufferedFileReader {
public:
    explicit BufferedFileReader(const std::filesystem::path& path)
        : path_(path), input_(path, std::ios::binary) {
        if (!input_) {
            throw std::runtime_error("Failed to open file for reading: " + path.string());
        }
        input_.seekg(0, std::ios::end);
        total_size_ = static_cast<std::size_t>(input_.tellg());
        input_.seekg(0, std::ios::beg);
    }

    // Read next chunk into provided buffer, returns bytes read
    std::size_t ReadChunk(std::uint8_t* buffer, std::size_t max_size) {
        if (!input_ || input_.eof()) {
            return 0;
        }
        input_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(max_size));
        std::size_t bytes_read = static_cast<std::size_t>(input_.gcount());
        bytes_read_ += bytes_read;
        return bytes_read;
    }

    // Read next chunk using internal stack buffer
    std::pair<const std::uint8_t*, std::size_t> ReadChunk() {
        std::size_t n = ReadChunk(chunk_.data(), chunk_.size());
        return {chunk_.data(), n};
    }

    std::size_t TotalSize() const noexcept { return total_size_; }
    std::size_t BytesRead() const noexcept { return bytes_read_; }
    bool HasMore() const noexcept { return bytes_read_ < total_size_; }
    bool IsOpen() const noexcept { return input_.is_open(); }

private:
    std::filesystem::path path_;
    std::ifstream input_;
    std::array<std::uint8_t, ChunkSize> chunk_;
    std::size_t total_size_ = 0;
    std::size_t bytes_read_ = 0;
};

// Buffered file writer with stack-allocated chunk buffer
template<std::size_t ChunkSize = kDefaultChunkSize>
class BufferedFileWriter {
public:
    explicit BufferedFileWriter(const std::filesystem::path& path)
        : path_(path), output_(path, std::ios::binary) {
        if (!output_) {
            throw std::runtime_error("Failed to open file for writing: " + path.string());
        }
    }

    ~BufferedFileWriter() {
        try {
            Flush();
        } catch (...) {
            // Don't throw from destructor
        }
    }

    // Write data to file (buffered)
    void Write(const std::uint8_t* data, std::size_t size) {
        std::size_t offset = 0;
        while (offset < size) {
            std::size_t available = chunk_.size() - buffer_pos_;
            std::size_t to_copy = std::min(available, size - offset);
            
            std::memcpy(chunk_.data() + buffer_pos_, data + offset, to_copy);
            buffer_pos_ += to_copy;
            offset += to_copy;
            
            if (buffer_pos_ == chunk_.size()) {
                FlushBuffer();
            }
        }
        bytes_written_ += size;
    }

    void Write(const std::vector<std::uint8_t>& data) {
        Write(data.data(), data.size());
    }

    // Flush any buffered data to disk
    void Flush() {
        if (buffer_pos_ > 0) {
            FlushBuffer();
        }
        if (output_) {
            output_.flush();
        }
    }

    std::size_t BytesWritten() const noexcept { return bytes_written_; }
    bool IsOpen() const noexcept { return output_.is_open(); }

private:
    void FlushBuffer() {
        if (buffer_pos_ > 0 && output_) {
            output_.write(reinterpret_cast<const char*>(chunk_.data()),
                         static_cast<std::streamsize>(buffer_pos_));
            if (!output_) {
                throw std::runtime_error("Failed to write to file: " + path_.string());
            }
            buffer_pos_ = 0;
        }
    }

    std::filesystem::path path_;
    std::ofstream output_;
    std::array<std::uint8_t, ChunkSize> chunk_;
    std::size_t buffer_pos_ = 0;
    std::size_t bytes_written_ = 0;
};

// Stream processor for large files - processes file in chunks without loading entire file into memory
template<typename ProcessFunc, std::size_t ChunkSize = kDefaultChunkSize>
void ProcessFileInChunks(const std::filesystem::path& input_path,
                         const std::filesystem::path& output_path,
                         ProcessFunc&& process) {
    BufferedFileReader<ChunkSize> reader(input_path);
    BufferedFileWriter<ChunkSize> writer(output_path);
    
    std::array<std::uint8_t, ChunkSize> output_buffer;
    
    while (reader.HasMore()) {
        auto [chunk_data, chunk_size] = reader.ReadChunk();
        if (chunk_size == 0) break;
        
        // Process chunk and write result
        std::size_t output_size = process(chunk_data, chunk_size, output_buffer.data(), output_buffer.size());
        if (output_size > 0) {
            writer.Write(output_buffer.data(), output_size);
        }
    }
    
    writer.Flush();
}

}  // namespace basefwx::filestream
