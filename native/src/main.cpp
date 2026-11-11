#include "format_parser.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void print_result(const babylon::ParseResult& result) {
  std::cout << "{\"status\":\"" << result.status << "\",\"format\":\""
            << result.format << "\",\"error\":";
  if (result.error.empty()) {
    std::cout << "null";
  } else {
    std::cout << "\"" << result.error << "\"";
  }
  std::cout << ",\"endian\":\"" << result.endian << "\",\"bits\":"
            << result.bits             << ",\"machine\":" << result.machine
            << ",\"object_type\":" << result.object_type
            << ",\"header_size\":" << result.header_size
            << ",\"entry_point\":" << result.entry_point
            << ",\"table_count\":" << result.table_count
            << ",\"table_bytes\":" << result.table_bytes
            << ",\"aux_count\":" << result.aux_count
            << ",\"aux_bytes\":" << result.aux_bytes
            << ",\"slices\":" << result.slices << "}\n";
}

}  // namespace

int main() {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(babylon::kMaxInputBytes);
  char block[8192];
  while (bytes.size() <= babylon::kMaxInputBytes && std::cin) {
    const auto remaining = babylon::kMaxInputBytes + 1 - bytes.size();
    const auto requested = std::min(sizeof(block), remaining);
    std::cin.read(block, static_cast<std::streamsize>(requested));
    const auto count = std::cin.gcount();
    if (count > 0) {
      const auto* first = reinterpret_cast<const std::uint8_t*>(block);
      bytes.insert(bytes.end(), first, first + count);
    }
    if (std::cin.eof()) {
      break;
    }
    if (std::cin.bad()) {
      std::cerr << "input_read_failed\n";
      return 2;
    }
  }

  if (bytes.size() > babylon::kMaxInputBytes) {
    std::cerr << "input_too_large\n";
    return 2;
  }
  print_result(babylon::parse(bytes));
  return 0;
}
