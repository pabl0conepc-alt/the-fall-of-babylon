#include "format_parser.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace babylon {
namespace {

constexpr std::uint64_t kMaxTableEntries = 8192;
constexpr std::uint64_t kMaxFatSlices = 64;

class View {
 public:
  View(const std::vector<std::uint8_t>& bytes, std::size_t base,
       std::size_t length)
      : bytes_(&bytes), base_(base), length_(length) {}

  std::size_t size() const { return length_; }

  bool contains(std::uint64_t offset, std::uint64_t length) const {
    return offset <= length_ && length <= length_ - offset;
  }

  bool read8(std::uint64_t offset, std::uint8_t& value) const {
    if (!contains(offset, 1)) return false;
    value = (*bytes_)[base_ + static_cast<std::size_t>(offset)];
    return true;
  }

  bool read16(std::uint64_t offset, bool little,
              std::uint16_t& value) const {
    std::uint8_t first = 0;
    std::uint8_t second = 0;
    if (!read8(offset, first) || !read8(offset + 1, second)) return false;
    value = little ? static_cast<std::uint16_t>(first | (second << 8))
                   : static_cast<std::uint16_t>((first << 8) | second);
    return true;
  }

  bool read32(std::uint64_t offset, bool little,
              std::uint32_t& value) const {
    std::uint16_t first = 0;
    std::uint16_t second = 0;
    if (!read16(offset, little, first) || !read16(offset + 2, little, second))
      return false;
    value = little ? static_cast<std::uint32_t>(first) |
                         (static_cast<std::uint32_t>(second) << 16)
                   : (static_cast<std::uint32_t>(first) << 16) |
                         static_cast<std::uint32_t>(second);
    return true;
  }

  bool read64(std::uint64_t offset, bool little,
              std::uint64_t& value) const {
    std::uint32_t first = 0;
    std::uint32_t second = 0;
    if (!read32(offset, little, first) || !read32(offset + 4, little, second))
      return false;
    value = little ? static_cast<std::uint64_t>(first) |
                         (static_cast<std::uint64_t>(second) << 32)
                   : (static_cast<std::uint64_t>(first) << 32) |
                         static_cast<std::uint64_t>(second);
    return true;
  }

  bool subview(std::uint64_t offset, std::uint64_t length, View& output) const {
    if (!contains(offset, length)) return false;
    output = View(*bytes_, base_ + static_cast<std::size_t>(offset),
                  static_cast<std::size_t>(length));
    return true;
  }

 private:
  const std::vector<std::uint8_t>* bytes_;
  std::size_t base_;
  std::size_t length_;
};

ParseResult result(std::string format, std::string status,
                  std::string error = {}) {
  ParseResult output;
  output.format = std::move(format);
  output.status = std::move(status);
  output.error = std::move(error);
  return output;
}

bool add_multiply_fits(std::uint64_t offset, std::uint64_t count,
                       std::uint64_t stride, std::uint64_t total,
                       std::uint64_t& bytes) {
  if (stride != 0 && count > std::numeric_limits<std::uint64_t>::max() / stride)
    return false;
  bytes = count * stride;
  return offset <= total && bytes <= total - offset;
}

ParseResult parse_pe(const View& file) {
  if (file.size() < 64) return result("PE", "truncated", "truncated_dos_header");
  std::uint32_t pe_offset = 0;
  if (!file.read32(0x3c, true, pe_offset) || pe_offset < 64 ||
      pe_offset > file.size())
    return result("PE", "malformed", "invalid_pe_offset");
  if (!file.contains(pe_offset, 4))
    return result("PE", "truncated", "truncated_pe_signature");
  std::uint32_t signature = 0;
  file.read32(pe_offset, true, signature);
  if (signature != 0x00004550)
    return result("PE", "malformed", "invalid_pe_signature");
  if (!file.contains(static_cast<std::uint64_t>(pe_offset) + 4, 20))
    return result("PE", "truncated", "truncated_coff_header");

  std::uint16_t machine = 0;
  std::uint16_t section_count = 0;
  std::uint16_t optional_size = 0;
  std::uint16_t characteristics = 0;
  file.read16(static_cast<std::uint64_t>(pe_offset) + 4, true, machine);
  file.read16(static_cast<std::uint64_t>(pe_offset) + 6, true, section_count);
  file.read16(static_cast<std::uint64_t>(pe_offset) + 20, true, optional_size);
  file.read16(static_cast<std::uint64_t>(pe_offset) + 22, true, characteristics);
  if (section_count > 96)
    return result("PE", "unsupported", "section_count_limit_exceeded");

  const std::uint64_t optional_offset =
      static_cast<std::uint64_t>(pe_offset) + 24;
  if (!file.contains(optional_offset, optional_size))
    return result("PE", "truncated", "truncated_optional_header");
  if (optional_size < 2)
    return result("PE", "malformed", "invalid_optional_header_size");

  std::uint16_t optional_magic = 0;
  file.read16(optional_offset, true, optional_magic);
  std::uint32_t bits = 0;
  std::uint64_t minimum_optional_size = 0;
  if (optional_magic == 0x10b) {
    bits = 32;
    minimum_optional_size = 96;
  } else if (optional_magic == 0x20b) {
    bits = 64;
    minimum_optional_size = 112;
  } else {
    return result("PE", "unsupported", "unsupported_optional_header");
  }
  if (optional_size < minimum_optional_size)
    return result("PE", "malformed", "incomplete_optional_header");

  std::uint32_t entry_point = 0;
  file.read32(optional_offset + 16, true, entry_point);
  const std::uint64_t section_table =
      optional_offset + static_cast<std::uint64_t>(optional_size);
  std::uint64_t section_bytes = 0;
  if (!add_multiply_fits(section_table, section_count, 40, file.size(),
                         section_bytes))
    return result("PE", "truncated", "truncated_section_table");

  for (std::uint64_t index = 0; index < section_count; ++index) {
    const auto header = section_table + index * 40;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_offset = 0;
    file.read32(header + 16, true, raw_size);
    file.read32(header + 20, true, raw_offset);
    if (raw_size > 0 && !file.contains(raw_offset, raw_size))
      return result("PE", "malformed", "section_data_out_of_bounds");
  }

  auto output = result("PE", "valid");
  output.endian = "little";
  output.bits = bits;
  output.machine = machine;
  output.object_type = characteristics;
  output.header_size = optional_offset + optional_size;
  output.entry_point = entry_point;
  output.table_count = section_count;
  output.table_bytes = section_bytes;
  return output;
}

bool read_elf_word(const View& file, std::uint64_t offset, bool is_64,
                   bool little, std::uint64_t& value) {
  if (is_64) return file.read64(offset, little, value);
  std::uint32_t value32 = 0;
  if (!file.read32(offset, little, value32)) return false;
  value = value32;
  return true;
}

ParseResult parse_elf(const View& file) {
  if (file.size() < 16) return result("ELF", "truncated", "truncated_ident");
  std::uint8_t elf_class = 0;
  std::uint8_t data_encoding = 0;
  std::uint8_t version = 0;
  file.read8(4, elf_class);
  file.read8(5, data_encoding);
  file.read8(6, version);
  if (elf_class != 1 && elf_class != 2)
    return result("ELF", "unsupported", "unsupported_elf_class");
  if (data_encoding != 1 && data_encoding != 2)
    return result("ELF", "malformed", "invalid_elf_endianness");
  if (version != 1)
    return result("ELF", "malformed", "invalid_elf_ident_version");

  const bool is_64 = elf_class == 2;
  const bool little = data_encoding == 1;
  const std::uint64_t header_size = is_64 ? 64 : 52;
  if (file.size() < header_size)
    return result("ELF", "truncated", "truncated_elf_header");

  std::uint16_t machine = 0;
  std::uint16_t object_type = 0;
  std::uint16_t elf_header_size = 0;
  std::uint16_t program_entry_size = 0;
  std::uint16_t program_count = 0;
  std::uint16_t section_entry_size = 0;
  std::uint16_t section_count = 0;
  std::uint16_t section_name_index = 0;
  std::uint32_t elf_version = 0;
  const std::uint64_t entry_offset = 24;
  const std::uint64_t program_offset_field = is_64 ? 32 : 28;
  const std::uint64_t section_offset_field = is_64 ? 40 : 32;
  const std::uint64_t header_size_field = is_64 ? 52 : 40;
  const std::uint64_t program_entry_size_field = is_64 ? 54 : 42;
  const std::uint64_t program_count_field = is_64 ? 56 : 44;
  const std::uint64_t section_entry_size_field = is_64 ? 58 : 46;
  const std::uint64_t section_count_field = is_64 ? 60 : 48;
  const std::uint64_t section_index_field = is_64 ? 62 : 50;
  file.read16(18, little, machine);
  file.read16(16, little, object_type);
  file.read32(20, little, elf_version);
  file.read16(header_size_field, little, elf_header_size);
  file.read16(program_entry_size_field, little, program_entry_size);
  file.read16(program_count_field, little, program_count);
  file.read16(section_entry_size_field, little, section_entry_size);
  file.read16(section_count_field, little, section_count);
  file.read16(section_index_field, little, section_name_index);

  std::uint64_t entry_point = 0;
  std::uint64_t program_offset = 0;
  std::uint64_t section_offset = 0;
  read_elf_word(file, entry_offset, is_64, little, entry_point);
  read_elf_word(file, program_offset_field, is_64, little, program_offset);
  read_elf_word(file, section_offset_field, is_64, little, section_offset);
  if (elf_header_size != header_size)
    return result("ELF", "malformed", "invalid_elf_header_size");
  if (elf_version != 1)
    return result("ELF", "malformed", "invalid_elf_header_version");

  std::uint32_t program_stride = is_64 ? 56 : 32;
  std::uint32_t section_stride = is_64 ? 64 : 40;
  if (program_count == 0xffff || (section_count == 0 && section_offset != 0))
    return result("ELF", "unsupported", "extended_table_count_unsupported");
  if ((section_count == 0 && section_name_index != 0) ||
      (section_count != 0 && section_name_index >= section_count))
    return result("ELF", "malformed", "invalid_section_name_index");
  if (program_count > kMaxTableEntries || section_count > kMaxTableEntries)
    return result("ELF", "unsupported", "table_count_limit_exceeded");
  if ((program_count != 0 && program_entry_size < program_stride) ||
      (section_count != 0 && section_entry_size < section_stride))
    return result("ELF", "malformed", "invalid_table_entry_size");
  if (program_count == 0 && program_offset != 0)
    return result("ELF", "malformed", "unexpected_program_table_offset");
  std::uint64_t program_bytes = 0;
  std::uint64_t section_bytes = 0;
  if (!add_multiply_fits(program_offset, program_count, program_entry_size,
                         file.size(), program_bytes))
    return result("ELF", "truncated", "truncated_program_table");
  if (!add_multiply_fits(section_offset, section_count, section_entry_size,
                         file.size(), section_bytes))
    return result("ELF", "truncated", "truncated_section_table");

  for (std::uint64_t index = 0; index < program_count; ++index) {
    const auto header = program_offset + index * program_entry_size;
    std::uint32_t type = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_size = 0;
    file.read32(header, little, type);
    if (is_64) {
      read_elf_word(file, header + 8, true, little, data_offset);
      read_elf_word(file, header + 32, true, little, data_size);
    } else {
      read_elf_word(file, header + 4, false, little, data_offset);
      read_elf_word(file, header + 16, false, little, data_size);
    }
    if (type != 0 && data_size > 0 && !file.contains(data_offset, data_size))
      return result("ELF", "malformed", "segment_data_out_of_bounds");
    (void)type;
  }
  for (std::uint64_t index = 0; index < section_count; ++index) {
    const auto header = section_offset + index * section_entry_size;
    std::uint32_t type = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_size = 0;
    file.read32(header + 4, little, type);
    if (is_64) {
      read_elf_word(file, header + 24, true, little, data_offset);
      read_elf_word(file, header + 32, true, little, data_size);
    } else {
      read_elf_word(file, header + 16, false, little, data_offset);
      read_elf_word(file, header + 20, false, little, data_size);
    }
    if (type != 8 && data_size > 0 && !file.contains(data_offset, data_size))
      return result("ELF", "malformed", "section_data_out_of_bounds");
  }

  auto output = result("ELF", "valid");
  output.endian = little ? "little" : "big";
  output.bits = is_64 ? 64 : 32;
  output.machine = machine;
  output.object_type = object_type;
  output.header_size = header_size;
  output.entry_point = entry_point;
  output.table_count = section_count;
  output.table_bytes = section_bytes;
  output.aux_count = program_count;
  output.aux_bytes = program_bytes;
  return output;
}

struct ThinMachO {
  ParseResult result;
  bool valid = false;
};

ThinMachO parse_macho_thin(const View& file) {
  if (file.size() < 4)
    return {result("Mach-O", "truncated", "truncated_mach_header"), false};
  std::uint32_t magic = 0;
  file.read32(0, true, magic);
  bool little = true;
  bool is_64 = false;
  if (magic == 0xcefaedfe) {
    little = false;
  } else if (magic == 0xfeedface) {
    little = true;
  } else if (magic == 0xcffaedfe) {
    little = false;
    is_64 = true;
  } else if (magic == 0xfeedfacf) {
    little = true;
    is_64 = true;
  } else {
    return {result("Mach-O", "unsupported", "unsupported_mach_magic"), false};
  }
  const std::uint64_t header_size = is_64 ? 32 : 28;
  if (file.size() < header_size)
    return {result("Mach-O", "truncated", "truncated_mach_header"), false};

  std::uint32_t machine = 0;
  std::uint32_t file_type = 0;
  std::uint32_t command_count = 0;
  std::uint32_t command_bytes = 0;
  file.read32(4, little, machine);
  file.read32(12, little, file_type);
  file.read32(16, little, command_count);
  file.read32(20, little, command_bytes);
  if (command_count > kMaxTableEntries)
    return {result("Mach-O", "unsupported", "load_command_limit_exceeded"),
            false};
  if (!file.contains(header_size, command_bytes))
    return {result("Mach-O", "truncated", "truncated_load_commands"), false};

  std::uint64_t cursor = header_size;
  const std::uint64_t command_end = header_size + command_bytes;
  for (std::uint64_t index = 0; index < command_count; ++index) {
    if (cursor > command_end || command_end - cursor < 8)
      return {result("Mach-O", "truncated", "truncated_load_command"), false};
    std::uint32_t command = 0;
    std::uint32_t command_size = 0;
    file.read32(cursor, little, command);
    file.read32(cursor + 4, little, command_size);
    if (command_size < 8 || command_size % 4 != 0 ||
        command_size > command_end - cursor)
      return {result("Mach-O", "malformed", "invalid_load_command_size"), false};

    if (command == 1 || command == 0x19) {
      const bool segment_64 = command == 0x19;
      const std::uint64_t minimum = segment_64 ? 72 : 56;
      if (command_size < minimum)
        return {result("Mach-O", "malformed", "incomplete_segment_command"),
                false};
      std::uint64_t file_offset = 0;
      std::uint64_t file_size = 0;
      std::uint32_t section_count = 0;
      const std::uint64_t file_offset_at = segment_64 ? cursor + 40 : cursor + 32;
      const std::uint64_t file_size_at = segment_64 ? cursor + 48 : cursor + 36;
      const std::uint64_t section_count_at = segment_64 ? cursor + 64 : cursor + 48;
      if (segment_64) {
        file.read64(file_offset_at, little, file_offset);
        file.read64(file_size_at, little, file_size);
      } else {
        std::uint32_t offset32 = 0;
        std::uint32_t size32 = 0;
        file.read32(file_offset_at, little, offset32);
        file.read32(file_size_at, little, size32);
        file_offset = offset32;
        file_size = size32;
      }
      file.read32(section_count_at, little, section_count);
      const std::uint64_t section_stride = segment_64 ? 80 : 68;
      std::uint64_t section_bytes = 0;
      if (!add_multiply_fits(minimum, section_count, section_stride, command_size,
                             section_bytes))
        return {result("Mach-O", "malformed", "invalid_segment_sections"),
                false};
      if (file_size > 0 && !file.contains(file_offset, file_size))
        return {result("Mach-O", "malformed", "segment_data_out_of_bounds"),
                false};
      for (std::uint64_t section = 0; section < section_count; ++section) {
        const auto section_header = cursor + minimum + section * section_stride;
        std::uint32_t section_offset = 0;
        std::uint32_t section_flags = 0;
        std::uint64_t section_size = 0;
        const std::uint64_t size_at = segment_64 ? section_header + 40
                                                  : section_header + 36;
        const std::uint64_t offset_at = segment_64 ? section_header + 48
                                                    : section_header + 40;
        const std::uint64_t flags_at = segment_64 ? section_header + 64
                                                   : section_header + 56;
        if (segment_64) {
          file.read64(size_at, little, section_size);
        } else {
          std::uint32_t size32 = 0;
          file.read32(size_at, little, size32);
          section_size = size32;
        }
        file.read32(offset_at, little, section_offset);
        file.read32(flags_at, little, section_flags);
        const std::uint32_t section_type = section_flags & 0xff;
        const bool zero_fill =
            section_type == 1 || section_type == 0x0c || section_type == 0x12;
        if (!zero_fill && section_size > 0 &&
            !file.contains(section_offset, section_size))
          return {result("Mach-O", "malformed", "section_data_out_of_bounds"),
                  false};
      }
    }
    cursor += command_size;
  }
  if (cursor != command_end)
    return {result("Mach-O", "malformed", "load_command_size_mismatch"), false};

  auto output = result("Mach-O", "valid");
  output.endian = little ? "little" : "big";
  output.bits = is_64 ? 64 : 32;
  output.machine = machine;
  output.object_type = file_type;
  output.header_size = header_size;
  output.table_count = command_count;
  output.table_bytes = command_bytes;
  return {output, true};
}

ParseResult parse_macho_fat(const View& file, bool little, bool fat_64) {
  if (file.size() < 8)
    return result("Mach-O", "truncated", "truncated_fat_header");
  std::uint32_t slice_count = 0;
  file.read32(4, little, slice_count);
  if (slice_count == 0 || slice_count > kMaxFatSlices)
    return result("Mach-O", "unsupported", "fat_slice_count_limit_exceeded");
  const std::uint64_t stride = fat_64 ? 32 : 20;
  std::uint64_t table_bytes = 0;
  if (!add_multiply_fits(8, slice_count, stride, file.size(), table_bytes))
    return result("Mach-O", "truncated", "truncated_fat_arch_table");

  struct SliceRange {
    std::uint64_t offset;
    std::uint64_t size;
  };
  std::array<SliceRange, kMaxFatSlices> ranges{};
  ParseResult first_slice;
  for (std::uint64_t index = 0; index < slice_count; ++index) {
    const auto entry = 8 + index * stride;
    std::uint32_t cpu_type = 0;
    std::uint64_t slice_offset = 0;
    std::uint64_t slice_size = 0;
    std::uint32_t slice_alignment = 0;
    file.read32(entry, little, cpu_type);
    if (fat_64) {
      file.read64(entry + 8, little, slice_offset);
      file.read64(entry + 16, little, slice_size);
      file.read32(entry + 24, little, slice_alignment);
    } else {
      std::uint32_t offset32 = 0;
      std::uint32_t size32 = 0;
      file.read32(entry + 8, little, offset32);
      file.read32(entry + 12, little, size32);
      file.read32(entry + 16, little, slice_alignment);
      slice_offset = offset32;
      slice_size = size32;
    }
    if (slice_alignment > 31 ||
        (slice_offset & ((std::uint64_t{1} << slice_alignment) - 1)) != 0 ||
        slice_offset < 8 + table_bytes ||
        !file.contains(slice_offset, slice_size))
      return result("Mach-O", "malformed", "fat_slice_out_of_bounds");
    for (std::uint64_t previous = 0; previous < index; ++previous) {
      const auto& range = ranges[static_cast<std::size_t>(previous)];
      if (slice_offset < range.offset + range.size &&
          range.offset < slice_offset + slice_size)
        return result("Mach-O", "malformed", "overlapping_fat_slices");
    }
    ranges[static_cast<std::size_t>(index)] = {slice_offset, slice_size};

    View slice(file);
    if (!file.subview(slice_offset, slice_size, slice))
      return result("Mach-O", "malformed", "fat_slice_out_of_bounds");
    auto parsed = parse_macho_thin(slice);
    if (!parsed.valid)
      return result("Mach-O", parsed.result.status, "invalid_fat_slice");
    if (parsed.result.machine != cpu_type)
      return result("Mach-O", "malformed", "fat_slice_cpu_mismatch");
    if (index == 0) first_slice = std::move(parsed.result);
  }
  first_slice.slices = slice_count;
  first_slice.table_count = slice_count;
  first_slice.table_bytes = table_bytes;
  return first_slice;
}

ParseResult parse_macho(const View& file) {
  if (file.size() < 4) return result("Mach-O", "truncated", "truncated_magic");
  std::uint32_t magic_little = 0;
  file.read32(0, true, magic_little);
  if (magic_little == 0xbebafeca) return parse_macho_fat(file, false, false);
  if (magic_little == 0xbfbafeca) return parse_macho_fat(file, false, true);
  if (magic_little == 0xcafebabe) return parse_macho_fat(file, true, false);
  if (magic_little == 0xcafebabf) return parse_macho_fat(file, true, true);
  return parse_macho_thin(file).result;
}

}  // namespace

ParseResult parse(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() > kMaxInputBytes)
    return result("unknown", "malformed", "input_too_large");
  const View file(bytes, 0, bytes.size());
  std::uint8_t first = 0;
  std::uint8_t second = 0;
  if (file.size() >= 2 && file.read8(0, first) && file.read8(1, second) &&
      first == 'M' && second == 'Z')
    return parse_pe(file);
  if (file.size() >= 4) {
    std::uint32_t magic = 0;
    file.read32(0, true, magic);
    if (magic == 0x464c457f) return parse_elf(file);
    if (magic == 0xfeedface || magic == 0xcefaedfe ||
        magic == 0xfeedfacf || magic == 0xcffaedfe ||
        magic == 0xbebafeca || magic == 0xbfbafeca ||
        magic == 0xcafebabe || magic == 0xcafebabf)
      return parse_macho(file);
  }
  return result("unknown", "unsupported", "unsupported_format");
}

}  // namespace babylon
