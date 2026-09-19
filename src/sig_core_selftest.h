#pragma once

// Machine-checked proof suite for sig_core: parser/renderer golden units,
// randomized generate->parse->search round-trip property tests against an
// independent brute-force oracle, scanner units, and trim invariance.
// Included by tests/test_sig_core.cpp (CI) and the plugin's fusion_selftest().
// Deterministic: fixed std::mt19937 seeds.

#include "sig_core.h"

#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

namespace sig_selftest{

using sig_core::u8;
using sig_core::u32;
using sig_core::u64;

constexpr u64 NO_IGNORE = 0xFFFFFFFFFFFFFFFFull;

//------------------------------------------------------------------ harness

struct ctx_t{
  bool (*log)(const char*);
  int failures = 0;
  int checks   = 0;

  void fail(const std::string& name, const std::string& detail){
    failures++;
    std::string line = "[FAIL] " + name + (detail.empty() ? "" : " | " + detail);
    log(line.c_str());
  }

  void check(const char* name, bool cond, const std::string& detail = ""){
    checks++;
    if (!cond)
      fail(name, detail);
  }

  void check_str(const char* name, const std::string& got, const std::string& want){
    checks++;
    if (got != want)
      fail(name, "got '" + got + "' want '" + want + "'");
  }
};

//------------------------------------------------------------------ independent oracle
// Written directly from the mask definition; shares no code with sig_core matching.

inline std::vector<u64> oracle_scan(const std::vector<u8>& image, const sig_core::pattern_t& p){
  std::vector<u64> out;
  if (p.empty() || p.size() > image.size())
    return out;
  for (size_t off = 0; off + p.size() <= image.size(); off++) {
    bool m = true;
    for (size_t j = 0; j < p.size(); j++) {
      u8 have = image[off + j] & p.mask[j];
      u8 want = p.bytes[j]      & p.mask[j];
      if (have != want) { m = false; break; }
    }
    if (m)
      out.push_back((u64)off);
  }
  return out;
}

// Plant a pattern occurrence at an offset: constrained bits from the pattern,
// unconstrained bits random.
inline void plant(std::vector<u8>& image, size_t off, const sig_core::pattern_t& p, std::mt19937& rng){
  for (size_t j = 0; j < p.size(); j++) {
    u8 keep  = p.bytes[j] & p.mask[j];
    u8 noise = (u8)(rng() & ~(u32)p.mask[j]);
    image[off + j] = (u8)(keep | noise);
  }
}

inline sig_core::pattern_t random_pattern(std::mt19937& rng, size_t len,
                                          bool allow_wild, bool allow_nibble,
                                          bool avoid_00_2a_literals){
  sig_core::pattern_t p;
  for (size_t i = 0; i < len; i++) {
    u32 roll = rng() % 100;
    if (allow_wild && roll < 25) {
      p.bytes.push_back((u8)rng());
      p.mask.push_back(0x00);
    } else if (allow_nibble && roll < 30) {
      u8 m = (rng() & 1) ? (u8)0xF0 : (u8)0x0F;
      p.bytes.push_back((u8)rng());
      p.mask.push_back(m);
    } else {
      u8 b = (u8)rng();
      if (avoid_00_2a_literals)
        while (b == 0x00 || b == 0x2A)
          b = (u8)rng();
      p.bytes.push_back(b);
      p.mask.push_back(0xFF);
    }
  }
  return p;
}

//------------------------------------------------------------------ A. parser / renderer golden units

inline void run_parser_tests(ctx_t& c){
  sig_core::parse_opts_t def;  // code_wild_00=true, code_wild_2a=true, allow_nibbles=true

  { // T1: IDA style basics
    auto r = sig_core::parse_ida("48 8B ? 05", def);
    c.check("T1 ida basic ok", r.ok, r.err);
    sig_core::pattern_t want;
    want.bytes = {0x48, 0x8B, 0x00, 0x05};
    want.mask  = {0xFF, 0xFF, 0x00, 0xFF};
    c.check("T1 ida basic pattern", r.ok && r.pat == want);
    c.check("T1 ida lowercase", sig_core::parse_ida("48 8b", def).ok);
    c.check("T1 ida comma",      sig_core::parse_ida("48, 8B", def).ok);
    auto q = sig_core::parse_ida("48 ?? 05", def);
    c.check("T1 ida dual ?? wildcard", q.ok && q.pat.size() == 3 && q.pat.is_wild(1));
  }

  { // T2: nibble wildcards
    auto r = sig_core::parse_ida("A?", def);
    c.check("T2 A? ok", r.ok, r.err);
    c.check("T2 A? bytes", r.ok && r.pat.bytes.size() == 1 && r.pat.bytes[0] == 0xA0);
    c.check("T2 A? mask",  r.ok && r.pat.mask.size() == 1 && r.pat.mask[0] == 0xF0);
    auto s = sig_core::parse_ida("?5", def);
    c.check("T2 ?5 ok", s.ok, s.err);
    c.check("T2 ?5 bytes", s.ok && s.pat.bytes.size() == 1 && s.pat.bytes[0] == 0x05);
    c.check("T2 ?5 mask",  s.ok && s.pat.mask.size() == 1 && s.pat.mask[0] == 0x0F);
    auto m = sig_core::parse_ida("48 A? ?5 ?", def);
    c.check("T2 mixed ok", m.ok && m.pat.size() == 4, m.err);
    sig_core::parse_opts_t nonib = def;
    nonib.allow_nibbles = false;
    c.check("T2 nibbles rejected when disabled", !sig_core::parse_ida("A?", nonib).ok);
  }

  { // T3: bug-1 regression pair — mask governs, literal 00 stays literal
    auto r = sig_core::parse_code("\\x83\\xF8\\x00 xxx", def);
    c.check("T3 mask parse ok", r.ok, r.err);
    c.check("T3 all literal", r.ok && r.pat.size() == 3 &&
          r.pat.mask[0] == 0xFF && r.pat.mask[1] == 0xFF && r.pat.mask[2] == 0xFF);
    if (r.ok) {
      u8 wrong[3] = {0x83, 0xF8, 0x05};
      u8 right[3] = {0x83, 0xF8, 0x00};
      c.check("T3 no false positive (cmp eax,5)",
              !sig_core::match_at(wrong, 3, r.pat, 0));
      c.check("T3 true match (cmp eax,0)",
              sig_core::match_at(right, 3, r.pat, 0));
    }
  }

  { // T4: maskless legacy heuristic documented: \x00 -> wildcard
    auto r = sig_core::parse_code("\\x83\\xF8\\x00", def);
    c.check("T4 ok", r.ok, r.err);
    c.check("T4 00 heuristic wildcards third byte",
            r.ok && r.pat.size() == 3 && r.pat.is_wild(2));
  }

  { // T5: maskless \x2A parameterized by code_wild_2a
    auto on = sig_core::parse_code("\\x83\\xF8\\x2A", def);
    c.check("T5 wild when enabled", on.ok && on.pat.is_wild(2));
    sig_core::parse_opts_t off = def;
    off.code_wild_2a = false;
    auto lit = sig_core::parse_code("\\x83\\xF8\\x2A", off);
    c.check("T5 literal when disabled", lit.ok && !lit.pat.is_wild(2) && lit.pat.bytes[2] == 0x2A);
  }

  { // T6: parse errors are surfaced, never silent (bug 9)
    auto must_fail = [&](const char* name, const sig_core::parse_result_t& r){
      c.check(name, !r.ok && !r.err.empty());
    };
    must_fail("T6 ida 'ZZ'",          sig_core::parse_ida("ZZ", def));
    must_fail("T6 ida '4'",           sig_core::parse_ida("4", def));
    must_fail("T6 ida empty",         sig_core::parse_ida("", def));
    must_fail("T6 ida '488B' strict", sig_core::parse_ida("488B", def));
    must_fail("T6 ida string lit",    sig_core::parse_ida("\"Hello\"", def));
    must_fail("T6 code mask len",     sig_core::parse_code("\\x48\\x8B x", def));
    must_fail("T6 code mask char",    sig_core::parse_code("\\x48\\x8B xy", def));
    must_fail("T6 code wild both",    sig_core::parse_code("\\x?? x", def));
    must_fail("T6 code truncated",    sig_core::parse_code("\\x4", def));
    must_fail("T6 code nibble",       sig_core::parse_code("\\x4?", def));
  }

  { // T7/T8: render golden strings (byte-exact contract with the previous renderer)
    sig_core::pattern_t p;
    p.bytes = {0x48, 0x8B, 0x00, 0x05};
    p.mask  = {0xFF, 0xFF, 0x00, 0xFF};

    sig_core::render_opts_t o;
    c.check_str("T7 ida default",
                sig_core::render(p, sig_core::SIGNATURE_STYLE_IDA, o).out, "48 8B ? 05");
    o.ida_dual_question = true;
    c.check_str("T7 ida dual ??",
                sig_core::render(p, sig_core::SIGNATURE_STYLE_IDA, o).out, "48 8B ?? 05");
    o.ida_dual_question = false;

    c.check_str("T8 code default",
                sig_core::render(p, sig_core::SIGNATURE_STYLE_CODE, o).out, "\\x48\\x8B\\x00\\x05");
    o.code_unicode_wild = true;
    c.check_str("T8 code unicode wild",
                sig_core::render(p, sig_core::SIGNATURE_STYLE_CODE, o).out, "\\x48\\x8B\\x2A\\x05");
    o.code_unicode_wild = false;
    o.code_append_mask = true;
    c.check_str("T8 code with mask",
                sig_core::render(p, sig_core::SIGNATURE_STYLE_CODE, o).out, "\\x48\\x8B\\x00\\x05 xx?x");
    o.code_append_mask = false;

    // wildcard byte value is dropped by CODE rendering
    sig_core::pattern_t q;
    q.bytes = {0x48, 0x8B, 0x37, 0x05};
    q.mask  = {0xFF, 0xFF, 0x00, 0xFF};
    c.check_str("T8 code drops wild value",
                sig_core::render(q, sig_core::SIGNATURE_STYLE_CODE, o).out, "\\x48\\x8B\\x00\\x05");
  }

  { // T9: hash golden vectors + 1-byte pattern renders full 8 hex digits (bug 5)
    c.check("T9 fnv1a 'a'",         sig_core::fnv1a((const u8*)"a", 1)         == 0xE40C292C);
    c.check("T9 fnv1a 'foobar'",    sig_core::fnv1a((const u8*)"foobar", 6)    == 0xBF9CF968);
    c.check("T9 crc32 'a'",         sig_core::crc32((const u8*)"a", 1)         == 0xE8B7BE43);
    c.check("T9 crc32 '123456789'", sig_core::crc32((const u8*)"123456789", 9) == 0xCBF43926);

    sig_core::pattern_t one;
    one.bytes = {0x50};
    one.mask  = {0xFF};
    auto h1 = sig_core::render(one, sig_core::SIGNATURE_STYLE_FNV1A, sig_core::render_opts_t{});
    auto h2 = sig_core::render(one, sig_core::SIGNATURE_STYLE_CRC32, sig_core::render_opts_t{});
    // "0x" + 8 hex digits, never truncated (the old renderer cut 1-byte hashes to 7 chars)
    c.check("T9 1-byte fnv length", h1.ok && h1.out.size() == 10, h1.out);
    c.check("T9 1-byte crc length", h2.ok && h2.out.size() == 10, h2.out);
    // Independent value check: parse the hex text back and compare to the hash.
    u32 expect_fnv = sig_core::fnv1a(one.bytes.data(), 1);
    u32 parsed_fnv = (u32)std::strtoul(h1.out.c_str() + 2, nullptr, 16);
    c.check("T9 1-byte fnv value", parsed_fnv == expect_fnv, h1.out);
  }

  { // T10: nibble render round-trips
    sig_core::pattern_t hi;
    hi.bytes = {0xA5}; hi.mask = {0xF0};
    sig_core::pattern_t lo;
    lo.bytes = {0xA5}; lo.mask = {0x0F};
    auto rhi = sig_core::render(hi, sig_core::SIGNATURE_STYLE_IDA, sig_core::render_opts_t{});
    auto rlo = sig_core::render(lo, sig_core::SIGNATURE_STYLE_IDA, sig_core::render_opts_t{});
    c.check_str("T10 render A?", rhi.out, "A?");
    c.check_str("T10 render ?5", rlo.out, "?5");
    c.check("T10 A? round-trips", sig_core::parse_ida(rhi.out, def).pat == hi);
    c.check("T10 ?5 round-trips", sig_core::parse_ida(rlo.out, def).pat == lo);
    c.check("T10 nibble in CODE style is an error",
            !sig_core::render(hi, sig_core::SIGNATURE_STYLE_CODE, sig_core::render_opts_t{}).ok);
  }

  { // T11: semantic equality
    sig_core::pattern_t w1, w2;
    w1.bytes = {0x37}; w1.mask = {0x00};
    w2.bytes = {0x00}; w2.mask = {0x00};
    c.check("T11 wild value ignored", w1 == w2);
    sig_core::pattern_t n1, n2;
    n1.bytes = {0xA5}; n1.mask = {0xF0};
    n2.bytes = {0xA0}; n2.mask = {0xF0};
    c.check("T11 constrained bits compared", n1 == n2);
    sig_core::pattern_t d1, d2;
    d1.bytes = {0x00}; d1.mask = {0x00};
    d2.bytes = {0x00}; d2.mask = {0xFF};
    c.check("T11 differing masks unequal", !(d1 == d2));
  }
}

//------------------------------------------------------------------ B. round-trip property proof

inline void run_roundtrip_tests(ctx_t& c, int trials){
  std::mt19937 rng(20260920u);
  sig_core::parse_opts_t def;

  for (int t = 0; t < trials; t++) {
    std::vector<u8> image(4096);
    for (auto& b : image)
      b = (u8)rng();

    size_t len = 1 + rng() % 32;
    bool   use_nibbles = (rng() % 2) == 0;
    sig_core::pattern_t orig = random_pattern(rng, len, true, use_nibbles, false);

    // Plant 1-3 occurrences (sometimes at offset 0 — address-0 regression, bug 6)
    u32 plants = 1 + rng() % 3;
    for (u32 k = 0; k < plants; k++) {
      size_t off = (k == 0 && (rng() % 4) == 0) ? 0
                                                : (size_t)(rng() % (image.size() - len));
      plant(image, off, orig, rng);
    }

    auto verify = [&](const char* style,
                      const sig_core::render_result_t& rr,
                      const sig_core::parse_opts_t& po){
      if (!rr.ok) {
        c.fail(std::string("R1 ") + style + " render failed", rr.err);
        return;
      }
      auto parsed = sig_core::parse(rr.out, po);
      if (!parsed.ok) {
        c.fail(std::string("R1 ") + style + " parse failed: '" + rr.out + "'", parsed.err);
        return;
      }
      if (!(parsed.pat == orig)) {
        c.fail(std::string("R1 ") + style + " parsed != original", rr.out);
        return;
      }
      // The searched pattern must find exactly the oracle's match set.
      std::vector<sig_core::mem_section_t> secs;
      sig_core::mem_section_t s;
      s.start_ea = 0;
      s.bytes    = image;
      secs.push_back(std::move(s));
      auto got  = sig_core::mem_find_all(secs, parsed.pat, 0, NO_IGNORE);
      auto want = oracle_scan(image, orig);
      if (got != want)
        c.fail(std::string("R1 ") + style + " match set != oracle", rr.out);
    };

    sig_core::render_opts_t o;

    // 1. IDA style — always applicable
    verify("IDA", sig_core::render(orig, sig_core::SIGNATURE_STYLE_IDA, o), def);

    if (orig.has_nibble_masks())
      continue; // CODE styles cannot represent nibble masks

    // 2. CODE + mask — self-describing, any literals
    sig_core::render_opts_t om;
    om.code_append_mask = true;
    verify("CODE+mask", sig_core::render(orig, sig_core::SIGNATURE_STYLE_CODE, om), def);

    // CODE maskless forms: literal bytes with value 00/2A are inexpressible
    // (the heuristic would read them back as wildcards)
    bool literal_ambiguous = false;
    for (size_t i = 0; i < orig.size(); i++)
      if (orig.mask[i] == 0xFF && (orig.bytes[i] == 0x00 || orig.bytes[i] == 0x2A))
        literal_ambiguous = true;

    // 3. CODE maskless with wildcards
    if (!literal_ambiguous) {
      verify("CODE maskless default",
             sig_core::render(orig, sig_core::SIGNATURE_STYLE_CODE, o), def);
      sig_core::render_opts_t ou;
      ou.code_unicode_wild = true;
      verify("CODE maskless unicode",
             sig_core::render(orig, sig_core::SIGNATURE_STYLE_CODE, ou), def);
    }

    // 4. CODE maskless literal-only
    bool all_literal = true;
    for (size_t i = 0; i < orig.size(); i++)
      if (orig.mask[i] != 0xFF)
        all_literal = false;
    if (all_literal && !literal_ambiguous)
      verify("CODE maskless literal-only",
             sig_core::render(orig, sig_core::SIGNATURE_STYLE_CODE, o), def);
  }
  c.check("R1 round-trip property suite", true); // per-trial failures reported above
}

inline void run_degenerate_tests(ctx_t& c){
  // R2: degenerate inputs
  sig_core::mem_section_t s;
  s.start_ea = 0x1000;
  s.bytes    = {};
  sig_core::pattern_t p;
  p.bytes = {0x41}; p.mask = {0xFF};
  c.check("R2 empty image no match", sig_core::mem_find_all({s}, p, 0, NO_IGNORE).empty());

  s.bytes = {0x41};
  sig_core::pattern_t big;
  big.bytes = {0x41, 0x42}; big.mask = {0xFF, 0xFF};
  c.check("R2 pattern longer than image", sig_core::mem_find_all({s}, big, 0, NO_IGNORE).empty());

  std::vector<u8> img(16, 0x77);
  sig_core::mem_section_t s2;
  s2.start_ea = 0;
  s2.bytes    = img;
  sig_core::pattern_t aw;
  aw.bytes = {0x00, 0x00}; aw.mask = {0x00, 0x00};
  auto all = sig_core::mem_find_all({s2}, aw, 0, NO_IGNORE);
  c.check("R2 all-wild matches every offset", all.size() == img.size() - aw.size() + 1);

  // R3: hash determinism
  sig_core::pattern_t h;
  h.bytes = {0x11, 0x22, 0x33}; h.mask = {0xFF, 0x00, 0xF0};
  auto a = sig_core::render(h, sig_core::SIGNATURE_STYLE_FNV1A, sig_core::render_opts_t{});
  sig_core::render_opts_t other;
  other.code_append_mask = true;
  auto b = sig_core::render(h, sig_core::SIGNATURE_STYLE_FNV1A, other);
  c.check("R3 hash deterministic", a.ok && b.ok && a.out == b.out);
}

//------------------------------------------------------------------ C. scanner units

inline void run_scanner_tests(ctx_t& c){
  { // M1: section boundaries
    sig_core::mem_section_t s1;
    s1.start_ea = 0x1000;
    s1.bytes.assign(0x1000, 0x11);
    s1.bytes.back() = 0xAA;
    sig_core::mem_section_t s2;
    s2.start_ea = 0x4000;
    s2.bytes.assign(0x10, 0xBB);
    std::vector<sig_core::mem_section_t> secs = {s1, s2};

    sig_core::pattern_t straddle;
    straddle.bytes = {0xAA, 0xBB}; straddle.mask = {0xFF, 0xFF};
    c.check("M1 no cross-section match",
            sig_core::mem_find(secs, straddle, 0, NO_IGNORE) == std::nullopt);

    sig_core::pattern_t inside;
    inside.bytes = {0x11, 0x11}; inside.mask = {0xFF, 0xFF};
    auto last = sig_core::mem_find_all(secs, inside, 0x1000, NO_IGNORE);
    // last byte is 0xAA, so the final window (end-2) does not match; the scanner
    // must stop at end-len windows — last match is end-3
    c.check("M1 never scans past section end", !last.empty() && last.back() == 0x1000 + 0x1000 - 3);
  }

  { // M2: ignore_ea skips exactly that start
    sig_core::mem_section_t s;
    s.start_ea = 0x1000;
    s.bytes.assign(8, 0x22);
    sig_core::pattern_t p;
    p.bytes = {0x22}; p.mask = {0xFF};
    auto got = sig_core::mem_find({s}, p, 0x1000, 0x1000);
    c.check("M2 ignore skips exact ea", got.has_value() && *got == 0x1001);
  }

  { // M3: start_at is inclusive
    sig_core::mem_section_t s;
    s.start_ea = 0x1000;
    s.bytes.assign(8, 0x22);
    sig_core::pattern_t p;
    p.bytes = {0x22}; p.mask = {0xFF};
    auto at = sig_core::mem_find({s}, p, 0x1005, NO_IGNORE);
    c.check("M3 start_at inclusive", at.has_value() && *at == 0x1005);
    auto before = sig_core::mem_find({s}, p, 0, NO_IGNORE);
    c.check("M3 start before section", before.has_value() && *before == 0x1000);
  }

  { // M4: invalid bytes never match — literal over invalid AND wild over invalid (bug 11)
    sig_core::mem_section_t s;
    s.start_ea = 0;
    s.bytes = {0x00, 0x00, 0x00};
    s.valid = {true, false, true};

    sig_core::pattern_t lit;
    lit.bytes = {0x00}; lit.mask = {0xFF};
    auto lm = sig_core::mem_find_all({s}, lit, 0, NO_IGNORE);
    c.check("M4 literal skips invalid byte", lm.size() == 2 && lm[0] == 0 && lm[1] == 2);

    sig_core::pattern_t wild;
    wild.bytes = {0x00, 0x00}; wild.mask = {0x00, 0x00};
    c.check("M4 wild window over invalid never matches",
            sig_core::mem_find_all({s}, wild, 0, NO_IGNORE).empty());
  }

  { // M5: short/empty sections skipped without crashing
    sig_core::mem_section_t tiny, empty;
    tiny.start_ea = 0x100;  tiny.bytes = {0x41};
    empty.start_ea = 0x200; empty.bytes = {};
    sig_core::pattern_t p;
    p.bytes = {0x41, 0x41}; p.mask = {0xFF, 0xFF};
    c.check("M5 short/empty sections", sig_core::mem_find({tiny, empty}, p, 0, NO_IGNORE) == std::nullopt);
  }

  { // M6: match at address 0 is returned (bug 6 analog)
    sig_core::mem_section_t s;
    s.start_ea = 0;
    s.bytes = {0x33};
    sig_core::pattern_t p;
    p.bytes = {0x33}; p.mask = {0xFF};
    auto got = sig_core::mem_find({s}, p, 0, NO_IGNORE);
    c.check("M6 match at address 0", got.has_value() && *got == 0);
  }
}

//------------------------------------------------------------------ D. trim invariance

inline void run_trim_tests(ctx_t& c, int trials){
  std::mt19937 rng(99020920u);

  int tested = 0;
  for (int t = 0; t < trials; t++) {
    std::vector<u8> image(1024);
    for (auto& b : image)
      b = (u8)rng();

    size_t len = 2 + rng() % 30;
    sig_core::pattern_t orig = random_pattern(rng, len, true, true, false);

    // Trim leading/trailing fully-wild bytes (same rule as builder_t::trim).
    sig_core::pattern_t copy = orig;
    while (!copy.empty() && copy.mask.front() == 0x00) {
      copy.bytes.erase(copy.bytes.begin());
      copy.mask.erase(copy.mask.begin());
    }
    while (!copy.empty() && copy.mask.back() == 0x00) {
      copy.bytes.pop_back();
      copy.mask.pop_back();
    }
    if (copy.empty())
      continue; // D2 covers this
    tested++;

    size_t lead = 0;
    while (lead < orig.size() && orig.mask[lead] == 0x00)
      lead++;

    // Pointwise invariance: wherever the original window fits,
    // orig matches at o  <=>  trimmed matches at o + lead.
    bool ok = true;
    for (size_t o = 0; o + orig.size() <= image.size(); o++) {
      bool m1 = sig_core::match_at(image.data(), image.size(), orig, o);
      bool m2 = sig_core::match_at(image.data(), image.size(), copy, o + lead);
      if (m1 != m2) { ok = false; break; }
    }
    if (!ok)
      c.fail("D1 trim match-set invariance", "trial mismatch");
  }
  c.check("D1 trim suite exercised", tested > trials / 2);

  { // D2: all-wild trims to empty
    sig_core::builder_t b;
    b.add(0x12, true);
    b.add(0x34, true);
    c.check("D2 has_bytes before trim", b.has_bytes);
    b.trim();
    c.check("D2 trims to empty", b.pat.empty());
    c.check("D2 has_bytes false after trim", !b.has_bytes);
  }
}

//------------------------------------------------------------------ entry point

// Returns failure count (0 = all proofs pass).
inline int run(bool (*log)(const char*), int roundtrip_trials = 1000){
  ctx_t c;
  c.log = log;

  log("[Fusion selftest] A. parser/renderer golden units");
  int before = c.failures;
  run_parser_tests(c);
  log(before == c.failures ? "[Fusion selftest] A. ok" : "[Fusion selftest] A. FAILED");

  log("[Fusion selftest] B. round-trip property proofs");
  before = c.failures;
  run_roundtrip_tests(c, roundtrip_trials);
  run_degenerate_tests(c);
  log(before == c.failures ? "[Fusion selftest] B. ok" : "[Fusion selftest] B. FAILED");

  log("[Fusion selftest] C. scanner units");
  before = c.failures;
  run_scanner_tests(c);
  log(before == c.failures ? "[Fusion selftest] C. ok" : "[Fusion selftest] C. FAILED");

  log("[Fusion selftest] D. trim invariance");
  before = c.failures;
  run_trim_tests(c, 200);
  log(before == c.failures ? "[Fusion selftest] D. ok" : "[Fusion selftest] D. FAILED");

  std::string summary = "[Fusion selftest] " + std::to_string(c.checks) + " checks, "
                      + std::to_string(c.failures) + " failure(s) - "
                      + (c.failures ? "FAIL" : "PASS");
  log(summary.c_str());
  return c.failures;
}

} // namespace sig_selftest
