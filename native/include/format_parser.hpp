#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace babylon {

constexpr std::size_t kMaxInputBytes = 1'048'576;

struct ParseResult {
  std::string status;
  std::string format;
  std::string error;
  std::string endian;
  std::uint32_t bits = 0;
  std::uint64_t machine = 0;
  std::uint64_t object_type = 0;
  std::uint64_t header_size = 0;
  std::uint64_t entry_point = 0;
  std::uint64_t table_count = 0;
  std::uint64_t table_bytes = 0;
  std::uint64_t aux_count = 0;
  std::uint64_t aux_bytes = 0;
  std::uint64_t slices = 0;
};

ParseResult parse(const std::vector<std::uint8_t>& bytes);

}  // namespace babylon
