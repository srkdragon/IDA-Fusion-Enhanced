#pragma once

// IDA-free signature core: parse / render / hash / match.
// Compiles standalone with no IDA SDK — the harness build is the independence proof.
// No UI calls (error()/warning()/msg()); failures are returned as values.
//
// Per-byte constraint mask, same semantics as IDA bin_search(BIN_SEARCH_BITMASK):
//   0xFF literal | 0x00 whole-byte wildcard | 0xF0 high-nibble fixed | 0x0F low-nibble fixed
// A byte matches iff ((db ^ pat) & mask) == 0.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sig_core{

using u8  = unsigned char;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

//------------------------------------------------------------------ pattern

struct pattern_t{
  std::vector<u8> bytes;  // byte values; size() == mask.size()
  std::vector<u8> mask;   // per-byte constraint mask

  size_t size()  const { return bytes.size(); }
  bool   empty() const { return bytes.empty(); }
  bool   is_wild(size_t i) const { return mask[i] == 0x00; }
  bool   has_nibble_masks() const {
    for (u8 m : mask)
      if (m != 0x00 && m != 0xFF)
        return true;
    return false;
  }

  // Semantic equality: same length, same constraints, same constrained bits.
  bool operator==(const pattern_t& r) const {
    if (bytes.size() != r.bytes.size())
      return false;
    for (size_t i = 0; i < bytes.size(); i++) {
      if (mask[i] != r.mask[i])
        return false;
      if ((bytes[i] & mask[i]) != (r.bytes[i] & mask[i]))
        return false;
    }
    return true;
  }
};

//------------------------------------------------------------------ parsing

struct parse_opts_t{
  bool code_wild_00  = true;  // maskless "\x00" token means wildcard (legacy heuristic)
  bool code_wild_2a  = true;  // maskless "\x2A" token means wildcard (unicode-wildcard mode round-trip)
  bool allow_nibbles = true;  // accept IDA-style "A?" / "?5"
};

struct parse_result_t{
  bool        ok = false;
  pattern_t   pat;
  std::string err;
  size_t      err_pos = 0;
};

// Auto-detects the style: contains "\x"/"\X" -> CODE, otherwise IDA.
parse_result_t parse(std::string_view text, const parse_opts_t& opts);
parse_result_t parse_ida(std::string_view text, const parse_opts_t& opts);
parse_result_t parse_code(std::string_view text, const parse_opts_t& opts);

//------------------------------------------------------------------ rendering

enum e_signature_style{
  SIGNATURE_STYLE_CODE  = 0,
  SIGNATURE_STYLE_IDA   = 1,
  SIGNATURE_STYLE_FNV1A = 2,
  SIGNATURE_STYLE_CRC32 = 3
};

struct render_opts_t{
  bool ida_dual_question = false;  // "??" instead of "?"            (FLAG_USE_DUAL_QUESTION_MARKS)
  bool code_unicode_wild = false;  // "\x2A" instead of "\x00"       (FLAG_USE_UNICODE_WILDCARD)
  bool code_append_mask  = false;  // trailing " xx?" mask           (FLAG_INCLUDE_MASK_FOR_CODE_SIGS)
};

struct render_result_t{
  bool        ok = false;
  std::string out;
  std::string err;
};

render_result_t render(const pattern_t& p, e_signature_style style, const render_opts_t& opts);

//------------------------------------------------------------------ hashes (over byte values; mask ignored)

u32 fnv1a(const u8* data, size_t len);  // 32-bit FNV-1a, basis 0x811C9DC5, prime 0x01000193
u32 crc32(const u8* data, size_t len);  // reflected CRC-32, poly 0xEDB88320, init/final 0xFFFFFFFF

//------------------------------------------------------------------ builder

struct builder_t{
  pattern_t pat;
  bool      has_bytes = false;

  void add(u8 byte, bool wildcard){
    pat.bytes.push_back(byte);
    pat.mask.push_back(wildcard ? 0x00 : 0xFF);
    has_bytes = true;
  }

  // Strip leading/trailing fully-wildcard bytes only; unconstrained bytes impose
  // nothing, so the match semantics of anchored matches are preserved.
  void trim(){
    while(!pat.empty() && pat.mask.back() == 0x00){
      pat.bytes.pop_back();
      pat.mask.pop_back();
    }
    while(!pat.empty() && pat.mask.front() == 0x00){
      pat.bytes.erase(pat.bytes.begin());
      pat.mask.erase(pat.mask.begin());
    }
    has_bytes = !pat.empty();
  }

  void reset(){
    pat.bytes.clear();
    pat.mask.clear();
    has_bytes = false;
  }

  render_result_t render(e_signature_style style, const render_opts_t& opts) const {
    return sig_core::render(pat, style, opts);
  }
};

//------------------------------------------------------------------ matching

inline bool match_at(const u8* image, size_t image_len, const pattern_t& p, size_t offset){
  if (p.empty() || offset + p.size() > image_len)
    return false;
  for (size_t j = 0; j < p.size(); j++)
    if (((image[offset + j] ^ p.bytes[j]) & p.mask[j]) != 0)
      return false;
  return true;
}

//------------------------------------------------------------------ memory-image scanner

struct mem_section_t{
  u64               start_ea;
  std::vector<u8>   bytes;
  std::vector<bool> valid;  // false = value unknown (uninitialized/unreadable); may be empty = all valid
};

// A match requires every covered byte to be valid (wildcards too — conservative
// for uniqueness verdicts) and the mask to match. Sections are scanned in
// address order (sorted defensively); a match never spans a section boundary.
// start_at is inclusive; a match starting exactly at ignore_ea is skipped.
std::optional<u64> mem_find(const std::vector<mem_section_t>& sections, const pattern_t& p,
                            u64 start_at, u64 ignore_ea);
std::vector<u64>   mem_find_all(const std::vector<mem_section_t>& sections, const pattern_t& p,
                                u64 start_at, u64 ignore_ea);

//================================================================== implementation

namespace detail{

inline bool hex_val(char c, int& v){
  if (c >= '0' && c <= '9') { v = c - '0';     return true; }
  if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
  if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
  return false;
}

inline bool is_space(char c)   { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
inline bool is_sep(char c)     { return is_space(c) || c == ','; }
inline void hex_byte(char* dst, u8 b){
  static const char* digits = "0123456789ABCDEF";
  dst[0] = digits[b >> 4];
  dst[1] = digits[b & 0xF];
}

// "0x" + 8 uppercase hex digits. Hand-rolled: the IDA SDK #defines snprintf
// away in plugin builds, so <cstdio> formatting is not portable here.
inline void append_hex8(std::string& out, u32 v){
  static const char* digits = "0123456789ABCDEF";
  out += "0x";
  for (int shift = 28; shift >= 0; shift -= 4)
    out.push_back(digits[(v >> shift) & 0xF]);
}

} // namespace detail

//------------------------------------------------------------------ IDA-style parse

// Tokens separated by whitespace/commas: "48" "8b" "?" "??" "A?" "?5".
// Strict two-hex-digit literal tokens (no little-endian words, no string literals).
inline parse_result_t parse_ida(std::string_view text, const parse_opts_t& opts){
  parse_result_t res;
  size_t i = 0;
  bool   any = false;

  while (i < text.size()) {
    while (i < text.size() && detail::is_sep(text[i]))
      i++;
    if (i >= text.size())
      break;

    size_t start = i;
    while (i < text.size() && !detail::is_sep(text[i]))
      i++;
    size_t tok_len = i - start;
    if (tok_len > 2) {
      res.err = "token longer than 2 characters (use two hex digits per byte)";
      res.err_pos = start;
      return res;
    }

    char c0 = text[start];
    char c1 = (tok_len == 2) ? text[start + 1] : '\0';
    int  v0, v1;

    if (c0 == '?') {
      if (tok_len == 1 || c1 == '?') {          // "?" / "??": whole-byte wildcard
        res.pat.bytes.push_back(0);
        res.pat.mask.push_back(0x00);
      } else if (detail::hex_val(c1, v1)) {     // "?5": low nibble fixed
        if (!opts.allow_nibbles) {
          res.err = "nibble wildcards not allowed";
          res.err_pos = start;
          return res;
        }
        res.pat.bytes.push_back((u8)v1);
        res.pat.mask.push_back(0x0F);
      } else {
        res.err = "malformed token";
        res.err_pos = start;
        return res;
      }
    } else if (detail::hex_val(c0, v0)) {
      if (tok_len == 1) {
        res.err = "single hex digit — use two digits per byte";
        res.err_pos = start;
        return res;
      }
      if (c1 == '?') {                          // "A?": high nibble fixed
        if (!opts.allow_nibbles) {
          res.err = "nibble wildcards not allowed";
          res.err_pos = start;
          return res;
        }
        res.pat.bytes.push_back((u8)(v0 << 4));
        res.pat.mask.push_back(0xF0);
      } else if (detail::hex_val(c1, v1)) {     // "48": literal
        res.pat.bytes.push_back((u8)((v0 << 4) | v1));
        res.pat.mask.push_back(0xFF);
      } else {
        res.err = "malformed token";
        res.err_pos = start;
        return res;
      }
    } else {
      res.err = "unexpected character";
      res.err_pos = start;
      return res;
    }

    any = true;
  }

  if (!any) {
    res.err = "empty signature";
    res.err_pos = 0;
    return res;
  }

  res.ok = true;
  return res;
}

//------------------------------------------------------------------ CODE-style parse

// "\xHH" / "\x??" tokens (x case-insensitive, whitespace/commas allowed between),
// optionally followed by whitespace and a mask of 'x'/'X'/'?' chars, one per byte.
//   Mask present  -> mask governs (in-token wildcard + mask is an error).
//   Mask absent   -> heuristic: token value in {0x00} (+ {0x2A} if code_wild_2a) means wildcard.
inline parse_result_t parse_code(std::string_view text, const parse_opts_t& opts){
  parse_result_t res;
  std::vector<bool> token_wild;
  size_t i = 0;

  while (true) {
    while (i < text.size() && detail::is_sep(text[i]))
      i++;
    if (i >= text.size())
      break;
    if (text[i] != '\\')
      break;                                    // mask (or garbage) follows

    size_t tok = i;
    if (i + 1 >= text.size() || (text[i + 1] != 'x' && text[i + 1] != 'X')) {
      res.err = "expected \\x";
      res.err_pos = tok;
      return res;
    }
    if (i + 3 >= text.size()) {
      res.err = "truncated \\x token";
      res.err_pos = tok;
      return res;
    }

    char c0 = text[i + 2], c1 = text[i + 3];
    int  v0, v1;
    i += 4;

    if (c0 == '?' && c1 == '?') {               // "\x??": whole-byte wildcard
      res.pat.bytes.push_back(0);
      res.pat.mask.push_back(0x00);
      token_wild.push_back(true);
    } else if (c0 == '?' || c1 == '?') {
      res.err = "nibble wildcards are not supported in CODE style";
      res.err_pos = tok;
      return res;
    } else if (detail::hex_val(c0, v0) && detail::hex_val(c1, v1)) {
      res.pat.bytes.push_back((u8)((v0 << 4) | v1));
      res.pat.mask.push_back(0xFF);
      token_wild.push_back(false);
    } else {
      res.err = "malformed \\x token";
      res.err_pos = tok;
      return res;
    }
  }

  if (token_wild.empty()) {
    res.err = "no \\x tokens found";
    res.err_pos = i;
    return res;
  }

  // Optional mask section: 'x'/'X'/'?' characters, one per byte.
  std::string trailing;
  while (i < text.size()) {
    char c = text[i++];
    if (detail::is_space(c))
      continue;
    if (c != ',' && c != 'x' && c != 'X' && c != '?') {
      res.err = "unexpected character in mask";
      res.err_pos = i - 1;
      return res;
    }
    if (c != ',')
      trailing.push_back(c == '?' ? '?' : 'x');
  }

  if (!trailing.empty()) {
    if (trailing.size() != token_wild.size()) {
      res.err = "mask length does not match byte count";
      res.err_pos = i;
      return res;
    }
    for (size_t k = 0; k < trailing.size(); k++) {
      if (token_wild[k]) {
        res.err = "wildcard specified in both token and mask";
        res.err_pos = i;
        return res;
      }
      if (trailing[k] == '?') {
        res.pat.mask[k] = 0x00;
        res.pat.bytes[k] = 0;                   // value unconstrained
      }
    }
  } else {
    // Heuristic fallback for maskless signatures (documented format limitation).
    for (size_t k = 0; k < res.pat.bytes.size(); k++) {
      u8 b = res.pat.bytes[k];
      bool wild = (opts.code_wild_00 && b == 0x00) || (opts.code_wild_2a && b == 0x2A);
      if (wild) {
        res.pat.mask[k] = 0x00;
        res.pat.bytes[k] = 0;
      }
    }
  }

  res.ok = true;
  return res;
}

//------------------------------------------------------------------ auto-detect

inline parse_result_t parse(std::string_view text, const parse_opts_t& opts){
  for (size_t i = 0; i + 1 < text.size(); i++) {
    if (text[i] == '\\' && (text[i + 1] == 'x' || text[i + 1] == 'X'))
      return parse_code(text, opts);
  }
  return parse_ida(text, opts);
}

//------------------------------------------------------------------ rendering

inline render_result_t render(const pattern_t& p, e_signature_style style, const render_opts_t& opts){
  render_result_t r;

  if (p.empty()) {
    r.err = "empty pattern";
    return r;
  }

  if (style == SIGNATURE_STYLE_FNV1A || style == SIGNATURE_STYLE_CRC32) {
    u32 h = (style == SIGNATURE_STYLE_FNV1A) ? fnv1a(p.bytes.data(), p.bytes.size())
                                             : crc32(p.bytes.data(), p.bytes.size());
    r.ok = true;
    detail::append_hex8(r.out, h);
    return r;
  }

  if (style == SIGNATURE_STYLE_IDA) {
    const char* wild = opts.ida_dual_question ? "??" : "?";
    for (size_t i = 0; i < p.size(); i++) {
      if (i > 0)
        r.out.push_back(' ');
      char h[2];
      switch (p.mask[i]) {
        case 0x00:
          r.out += wild;
          break;
        case 0xFF:
          detail::hex_byte(h, p.bytes[i]);
          r.out.append(h, 2);
          break;
        case 0xF0:
          detail::hex_byte(h, p.bytes[i]);
          r.out.push_back(h[0]);
          r.out.push_back('?');
          break;
        case 0x0F:
          detail::hex_byte(h, p.bytes[i]);
          r.out.push_back('?');
          r.out.push_back(h[1]);
          break;
        default:
          r.err = "unsupported mask value for IDA style";
          return r;
      }
    }
    r.ok = true;
    return r;
  }

  if (style == SIGNATURE_STYLE_CODE) {
    if (p.has_nibble_masks()) {
      r.err = "nibble wildcards cannot be rendered in CODE style";
      return r;
    }
    for (size_t i = 0; i < p.size(); i++) {
      r.out += "\\x";
      char h[2];
      if (p.mask[i] == 0x00) {
        detail::hex_byte(h, opts.code_unicode_wild ? 0x2A : 0x00);
        r.out.append(h, 2);
      } else {
        detail::hex_byte(h, p.bytes[i]);
        r.out.append(h, 2);
      }
    }
    if (opts.code_append_mask) {
      r.out.push_back(' ');
      for (size_t i = 0; i < p.size(); i++)
        r.out.push_back(p.mask[i] == 0x00 ? '?' : 'x');
    }
    r.ok = true;
    return r;
  }

  r.err = "unknown style";
  return r;
}

//------------------------------------------------------------------ hashes

inline u32 fnv1a(const u8* data, size_t len){
  u32 hash = 0x811c9dc5;
  for (size_t i = 0; i < len; i++)
    hash = (hash ^ data[i]) * 0x01000193;
  return hash;
}

inline u32 crc32(const u8* data, size_t len){
  u32 crc = 0xFFFFFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int b = 0; b < 8; b++)
      crc = (crc >> 1) ^ (0xEDB88320 & (0u - (crc & 1)));
  }
  return ~crc;
}

//------------------------------------------------------------------ scanner

namespace detail{

inline bool section_offset_match(const mem_section_t& s, const pattern_t& p, size_t off){
  for (size_t j = 0; j < p.size(); j++) {
    if (!s.valid.empty() && !s.valid[off + j])
      return false;
    if (((s.bytes[off + j] ^ p.bytes[j]) & p.mask[j]) != 0)
      return false;
  }
  return true;
}

inline std::vector<size_t> section_order(const std::vector<mem_section_t>& sections){
  std::vector<size_t> idx(sections.size());
  for (size_t i = 0; i < idx.size(); i++)
    idx[i] = i;
  for (size_t i = 1; i < idx.size(); i++)        // small n; keep it dependency-free
    for (size_t j = i; j > 0 && sections[idx[j - 1]].start_ea > sections[idx[j]].start_ea; j--) {
      size_t t = idx[j - 1];
      idx[j - 1] = idx[j];
      idx[j] = t;
    }
  return idx;
}

} // namespace detail

inline std::optional<u64> mem_find(const std::vector<mem_section_t>& sections, const pattern_t& p,
                                   u64 start_at, u64 ignore_ea){
  if (p.empty())
    return std::nullopt;

  for (size_t si : detail::section_order(sections)) {
    const mem_section_t& s = sections[si];
    const size_t len = s.bytes.size();
    if (len < p.size())
      continue;
    if (start_at >= s.start_ea + len)
      continue;

    size_t off = (start_at > s.start_ea) ? (size_t)(start_at - s.start_ea) : 0;
    for (size_t o = off; o + p.size() <= len; o++) {
      u64 a = s.start_ea + o;
      if (a == ignore_ea)
        continue;
      if (detail::section_offset_match(s, p, o))
        return a;
    }
  }
  return std::nullopt;
}

inline std::vector<u64> mem_find_all(const std::vector<mem_section_t>& sections, const pattern_t& p,
                                     u64 start_at, u64 ignore_ea){
  std::vector<u64> out;
  if (p.empty())
    return out;

  for (size_t si : detail::section_order(sections)) {
    const mem_section_t& s = sections[si];
    const size_t len = s.bytes.size();
    if (len < p.size())
      continue;
    if (start_at >= s.start_ea + len)
      continue;

    size_t off = (start_at > s.start_ea) ? (size_t)(start_at - s.start_ea) : 0;
    for (size_t o = off; o + p.size() <= len; o++) {
      u64 a = s.start_ea + o;
      if (a == ignore_ea)
        continue;
      if (detail::section_offset_match(s, p, o))
        out.push_back(a);
    }
  }
  return out;
}

} // namespace sig_core
