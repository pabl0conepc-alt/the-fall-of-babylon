#include "format_parser.hpp"

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

void put16(std::vector<std::uint8_t>& bytes, std::size_t offset,
           std::uint16_t value, bool little = true) {
  for (std::size_t index = 0; index < 2; ++index) {
    const auto shift = static_cast<unsigned>((little ? index : 1 - index) * 8);
    bytes[offset + index] = static_cast<std::uint8_t>(value >> shift);
  }
}

void put32(std::vector<std::uint8_t>& bytes, std::size_t offset,
           std::uint32_t value, bool little = true) {
  for (std::size_t index = 0; index < 4; ++index) {
    const auto shift = static_cast<unsigned>((little ? index : 3 - index) * 8);
    bytes[offset + index] = static_cast<std::uint8_t>(value >> shift);
  }
}

void put64(std::vector<std::uint8_t>& bytes, std::size_t offset,
           std::uint64_t value, bool little = true) {
  for (std::size_t index = 0; index < 8; ++index) {
    const auto shift = static_cast<unsigned>((little ? index : 7 - index) * 8);
    bytes[offset + index] = static_cast<std::uint8_t>(value >> shift);
  }
}

void expect(const babylon::ParseResult& result, const std::string& format,
            const std::string& status) {
  if (result.format != format || result.status != status) {
    std::cerr << "expected " << format << "/" << status << ", got "
              << result.format << "/" << result.status << " (" << result.error
              << ")\n";
    std::exit(1);
  }
}

std::vector<std::uint8_t> make_pe() {
  std::vector<std::uint8_t> bytes(368, 0);
  bytes[0] = 'M';
  bytes[1] = 'Z';
  put32(bytes, 0x3c, 64);
  bytes[64] = 'P';
  bytes[65] = 'E';
  put16(bytes, 68, 0x8664);
  put16(bytes, 70, 1);
  put16(bytes, 84, 240);
  put16(bytes, 86, 2);
  put16(bytes, 88, 0x20b);
  put32(bytes, 104, 0x1000);
  return bytes;
}

std::vector<std::uint8_t> make_pe32() {
  std::vector<std::uint8_t> bytes(352, 0);
  bytes[0] = 'M';
  bytes[1] = 'Z';
  put32(bytes, 0x3c, 64);
  bytes[64] = 'P';
  bytes[65] = 'E';
  put16(bytes, 68, 0x014c);
  put16(bytes, 70, 1);
  put16(bytes, 84, 224);
  put16(bytes, 86, 2);
  put16(bytes, 88, 0x10b);
  return bytes;
}

std::vector<std::uint8_t> make_elf64() {
  std::vector<std::uint8_t> bytes(185, 0);
  bytes[0] = 0x7f;
  bytes[1] = 'E';
  bytes[2] = 'L';
  bytes[3] = 'F';
  bytes[4] = 2;
  bytes[5] = 1;
  bytes[6] = 1;
  put16(bytes, 16, 2);
  put16(bytes, 18, 62);
  put32(bytes, 20, 1);
  put64(bytes, 24, 0x400000);
  put64(bytes, 32, 64);
  put64(bytes, 40, 120);
  put16(bytes, 52, 64);
  put16(bytes, 54, 56);
  put16(bytes, 56, 1);
  put16(bytes, 58, 64);
  put16(bytes, 60, 1);
  put32(bytes, 64, 1);
  put64(bytes, 72, 184);
  put64(bytes, 96, 1);
  put32(bytes, 124, 1);
  put64(bytes, 144, 184);
  put64(bytes, 152, 1);
  bytes[184] = 0x90;
  return bytes;
}

std::vector<std::uint8_t> make_elf32_big_endian() {
  std::vector<std::uint8_t> bytes(52, 0);
  bytes[0] = 0x7f;
  bytes[1] = 'E';
  bytes[2] = 'L';
  bytes[3] = 'F';
  bytes[4] = 1;
  bytes[5] = 2;
  bytes[6] = 1;
  put16(bytes, 16, 2, false);
  put16(bytes, 18, 3, false);
  put32(bytes, 20, 1, false);
  put32(bytes, 24, 0x1000, false);
  put16(bytes, 40, 52, false);
  return bytes;
}

std::vector<std::uint8_t> make_macho64() {
  std::vector<std::uint8_t> bytes(40, 0);
  bytes[0] = 0xcf;
  bytes[1] = 0xfa;
  bytes[2] = 0xed;
  bytes[3] = 0xfe;
  put32(bytes, 4, 0x01000007);
  put32(bytes, 12, 2);
  put32(bytes, 16, 1);
  put32(bytes, 20, 8);
  put32(bytes, 32, 0x1b);
  put32(bytes, 36, 8);
  return bytes;
}

void put_macho32_big(std::vector<std::uint8_t>& bytes, std::size_t offset) {
  bytes[offset] = 0xfe;
  bytes[offset + 1] = 0xed;
  bytes[offset + 2] = 0xfa;
  bytes[offset + 3] = 0xce;
  put32(bytes, offset + 4, 7, false);
}

std::vector<std::uint8_t> make_fat_macho() {
  std::vector<std::uint8_t> bytes(104, 0);
  bytes[0] = 0xca;
  bytes[1] = 0xfe;
  bytes[2] = 0xba;
  bytes[3] = 0xbe;
  put32(bytes, 4, 2, false);
  put32(bytes, 8, 7, false);
  put32(bytes, 16, 48, false);
  put32(bytes, 20, 28, false);
  put32(bytes, 28, 7, false);
  put32(bytes, 36, 76, false);
  put32(bytes, 40, 28, false);
  put_macho32_big(bytes, 48);
  put_macho32_big(bytes, 76);
  put32(bytes, 48 + 12, 2, false);
  put32(bytes, 76 + 12, 2, false);
  return bytes;
}

}  // namespace

int main() {
  std::vector<std::uint8_t> oversized(babylon::kMaxInputBytes + 1, 0);
  const auto oversized_result = babylon::parse(oversized);
  expect(oversized_result, "unknown", "malformed");
  if (oversized_result.error != "input_too_large") return 1;

  auto pe = make_pe();
  const auto pe_result = babylon::parse(pe);
  expect(pe_result, "PE", "valid");
  if (pe_result.bits != 64 || pe_result.table_count != 1 ||
      pe_result.entry_point != 0x1000)
    return 1;
  const auto pe32_result = babylon::parse(make_pe32());
  expect(pe32_result, "PE", "valid");
  if (pe32_result.bits != 32 || pe32_result.machine != 0x014c) return 1;
  pe.resize(pe.size() - 1);
  expect(babylon::parse(pe), "PE", "truncated");
  pe = make_pe();
  put32(pe, 0x3c, 0xffffffff);
  expect(babylon::parse(pe), "PE", "malformed");
  pe = make_pe();
  put32(pe, 348, 368);
  put32(pe, 344, 1);
  expect(babylon::parse(pe), "PE", "malformed");

  auto elf64 = make_elf64();
  const auto elf_result = babylon::parse(elf64);
  expect(elf_result, "ELF", "valid");
  if (elf_result.bits != 64 || elf_result.aux_count != 1 ||
      elf_result.table_count != 1 || elf_result.entry_point != 0x400000)
    return 1;
  elf64[184] = 0;
  put64(elf64, 72, 185);
  expect(babylon::parse(elf64), "ELF", "malformed");
  elf64 = make_elf64();
  elf64.resize(70);
  expect(babylon::parse(elf64), "ELF", "truncated");
  const auto elf32 = babylon::parse(make_elf32_big_endian());
  expect(elf32, "ELF", "valid");
  if (elf32.bits != 32 || elf32.endian != "big") return 1;

  const auto macho_result = babylon::parse(make_macho64());
  expect(macho_result, "Mach-O", "valid");
  if (macho_result.bits != 64 || macho_result.table_count != 1) return 1;
  auto macho_bad = make_macho64();
  put32(macho_bad, 36, 0);
  expect(babylon::parse(macho_bad), "Mach-O", "malformed");
  macho_bad = make_macho64();
  macho_bad.resize(36);
  expect(babylon::parse(macho_bad), "Mach-O", "truncated");
  const auto fat_result = babylon::parse(make_fat_macho());
  expect(fat_result, "Mach-O", "valid");
  if (fat_result.slices != 2) return 1;
  auto fat_bad = make_fat_macho();
  put32(fat_bad, 16, 0xffffffff, false);
  expect(babylon::parse(fat_bad), "Mach-O", "malformed");

  std::cout << "format parser tests passed\n";
  return 0;
}
