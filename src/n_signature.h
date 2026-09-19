#pragma once

// Signature generation and search on top of the IDA SDK.
// All pattern parsing / rendering / matching lives in the IDA-free sig_core,
// so generate->search round-trips are provable outside IDA (see sig_core_selftest.h).

#include "sig_core.h"

using sig_core::e_signature_style;
using sig_core::SIGNATURE_STYLE_CODE;
using sig_core::SIGNATURE_STYLE_IDA;
using sig_core::SIGNATURE_STYLE_FNV1A;
using sig_core::SIGNATURE_STYLE_CRC32;

struct s_signature_find_settings{
  bool silent             = true;   // Output information
  bool stop_at_first      = false;  // Stop at first found signature
  ea_t ignore_addr        = 0;      // Ignore a selected address
  ea_t start_at_addr      = 0;      // Start scanning from an address
  bool jump_to_found_addr = false;  // Jump to the found address
};

namespace n_signature{

  // Render options mapped from the persisted settings flags.
  static sig_core::render_opts_t make_render_opts(){
    sig_core::render_opts_t o;
    o.ida_dual_question = (n_settings::data & FLAG_USE_DUAL_QUESTION_MARKS) != 0;
    o.code_unicode_wild = (n_settings::data & FLAG_USE_UNICODE_WILDCARD) != 0;
    o.code_append_mask  = (n_settings::data & FLAG_INCLUDE_MASK_FOR_CODE_SIGS) != 0;
    return o;
  }

  // Parse options for user-supplied signatures: both legacy CODE heuristics
  // (maskless \x00 / \x2A mean wildcard) and IDA-style nibble wildcards stay enabled.
  static sig_core::parse_opts_t make_parse_opts(){
    return sig_core::parse_opts_t{};
  }

  // Compile a pattern into the structure bin_search consumes
  // (same layout the SDK's raw image+mask overload builds internally).
  static void compile_pattern(const sig_core::pattern_t& pat, compiled_binpat_vec_t* out){
    compiled_binpat_t& bv = out->push_back();
    bv.bytes.append(pat.bytes.data(), (int)pat.bytes.size());
    bv.mask.append(pat.mask.data(), (int)pat.mask.size());
  }

  // Core search over a compiled pattern. BADADDR is the only not-found sentinel;
  // address 0 is a legitimate match.
  static std::vector<ea_t> find_pattern(const sig_core::pattern_t& pat, s_signature_find_settings find_settings){
    std::vector<ea_t> ea;

    if(!find_settings.silent){
      hide_wait_box();
      show_wait_box("[Fusion] Searching...");
    }

    ea_t ea_min = 0;
    ea_t ea_max = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    compiled_binpat_vec_t sig_data;
    compile_pattern(pat, &sig_data);

    ea_t addr = (find_settings.start_at_addr > 0 ? find_settings.start_at_addr : ea_min) - 1;

    while(true){
      // BIN_SEARCH_CASE: raw bytes must match exactly (0x61 must not match 0x41).
      // BIN_SEARCH_BITMASK: mask[i] is a per-byte AND mask (0xFF literal, 0x00 wildcard,
      // 0xF0/0x0F nibble) — identical semantics to sig_core::match_at.
      addr = bin_search(addr + 1, ea_max, sig_data,
                        BIN_SEARCH_FORWARD | BIN_SEARCH_CASE | BIN_SEARCH_BITMASK);

      if(addr == BADADDR)
        break;

      if(addr == find_settings.ignore_addr)
        continue;

      // Jump to the first address we find
      if(find_settings.jump_to_found_addr && ea.empty())
        jumpto(addr);

      ea.push_back(addr);

      if(!find_settings.silent){
        replace_wait_box("[Fusion] Searching...\n\nFound %zu signature%s", ea.size(), ea.size() > 1 ? "s" : "");
        msg("[Fusion] %zu. Found at address `0x%llX`\n", ea.size(), addr);
      }

      if(find_settings.stop_at_first)
        break;
    }

    if(!find_settings.silent){
      hide_wait_box();

      if(ea.empty())
        msg("[Fusion] No addresses found from signature\n");
      else if(ea.size() > 1)
        msg("[Fusion] Found %zu addresses\n", ea.size());

      beep(beep_default);
    }

    return ea;
  }

  // Search a user-supplied signature string (IDA or CODE style). Parse failures
  // are reported instead of silently returning "no addresses found".
  static std::vector<ea_t> find(std::string signature, s_signature_find_settings find_settings){
    sig_core::parse_result_t parsed = sig_core::parse(signature, make_parse_opts());

    if(!parsed.ok){
      hide_wait_box();
      msg("[Fusion] Signature parse error at position %zu: %s\n",
          parsed.err_pos, parsed.err.c_str());
      warning("[Fusion] Invalid signature:\n\n%s\n\n(input position %zu)",
              parsed.err.c_str(), parsed.err_pos);
      beep(beep_default);
      return {};
    }

    return find_pattern(parsed.pat, find_settings);
  }

  // Process one instruction into the signature builder.
  // Returns: 0 = stop generation, 1 = continue via next_not_tail, 2 = iterator already advanced (CC/90 step).
  static i32 process_instruction(ea_t addr, sig_core::builder_t& signature_generator,
                                 func_item_iterator_t& iterator, ea_t range_end,
                                 bool respect_boundaries, insn_t* out_insn = nullptr){
    // Never step past the effective range end (the user's selection in range mode).
    if(addr >= range_end)
      return 0;

    insn_t insn;
    if(!decode_insn(&insn, addr))
      return 0;

    // Check if we've reached a function boundary (if enabled)
    if(respect_boundaries){
      func_t* func = get_func(addr);
      if(func != nullptr && addr >= func->end_ea)
        return 0; // Don't go past function end
    }

    // Get the imm offset for this instruction
    i32 imm_offset = n_utils::get_insn_imm_offset(&insn);

    // Check if wildcards are enabled
    bool use_wildcards = !(n_settings::data & FLAG_DISABLE_WILDCARDS);

    // A selection ending mid-instruction contributes only the in-range bytes.
    ea_t op_end = addr + insn.size;
    if(op_end > range_end)
      op_end = range_end;

    for(ea_t op_addr = addr; op_addr < op_end; op_addr++)
      signature_generator.add(get_byte(op_addr),
                               use_wildcards && imm_offset > 0 && (op_addr - addr) >= imm_offset);

    if(out_insn != nullptr)
      *out_insn = insn;

    // These instructions are not parsed correctly by ida, so lets fix it
    if(get_byte(addr) == 0xCC || get_byte(addr) == 0x90){
      iterator.set_range(addr + 1, range_end);
      return 2; // Continue but skip next_not_tail
    }

    return iterator.next_not_tail() ? 1 : 0;
  }

  // Create a signature for target_ea (defaults to the cursor). Returns the
  // rendered signature, empty on failure — the selftest closes the create->find
  // loop through this return value.
  static std::string create(e_signature_style style, ea_t target_ea = BADADDR, bool verbose = true){
    bool explicit_ea = (target_ea != BADADDR);
    if(!explicit_ea)
      target_ea = get_screen_ea();

    if(!(n_settings::data & FLAG_ALLOW_SIG_CREATION_IN_DR) && get_func_num(target_ea) == 0xFFFFFFFF){
      hide_wait_box();
      if(verbose)
        warning("[Fusion] `0x%llX` Is not in a valid assembly region.\n\nHint: You can disable this in the settings of Fusion.", target_ea);
      return "";
    }

    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();

    sig_core::builder_t signature_generator;
    ea_t                ea_region_start = 0;
    ea_t                ea_region_end   = 0;
    ea_t                ea_min          = 0;
    ea_t                ea_max          = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    if(verbose)
      replace_wait_box("[Fusion] Creating signature for `0x%llX`", target_ea);

    // If we have selected a range of assembly code, sig exactly those bytes (no trim — user chose them)
    bool selected_range = !explicit_ea
                          && (n_settings::data & FLAG_COPY_SELECTED_BYTES_ONLY_IN_RANGE)
                          && read_range_selection(nullptr, &ea_region_start, &ea_region_end)
                          && ea_region_end > ea_region_start;
    if(selected_range){
      func_item_iterator_t iterator;
      iterator.set_range(ea_region_start, ea_region_end);
      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        // No boundary truncation in range mode: the user explicitly chose these bytes.
        if(process_instruction(addr, signature_generator, iterator, ea_region_end, false) == 0)
          break;
      }
    }
    else{
      ea_t last_found_address = ea_min;

      // Generate memory for the mnemonic opcodes list
      u32 mnemonic_opcodes_len  = 5000/*~4.9KB*/;
      i8* mnemonic_opcodes      = (n_settings::data & FLAG_SHOW_MNEMONIC_OPCODES_SIGGED) ? (i8*)malloc(mnemonic_opcodes_len) : nullptr;

      if(mnemonic_opcodes != nullptr)
        memset(mnemonic_opcodes, 0, mnemonic_opcodes_len);

      func_item_iterator_t iterator;
      iterator.set_range(target_ea, ea_max);
      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        insn_t insn;
        i32 result = process_instruction(addr, signature_generator, iterator, ea_max,
                                         (n_settings::data & FLAG_RESPECT_FUNCTION_BOUNDARIES) != 0,
                                         &insn);
        if(result == 0)
          break;

        // Add details on whats going on in relation to this creation
        if(mnemonic_opcodes != nullptr){
          qsnprintf(mnemonic_opcodes + strlen(mnemonic_opcodes), mnemonic_opcodes_len - strlen(mnemonic_opcodes), "+ %s\n", insn.get_canon_mnem(PH));
          if(verbose)
            replace_wait_box("[Fusion] Creating signature for `0x%llX`\n\n%s", target_ea, mnemonic_opcodes);
        }

        // Attempt to search for this signature, if nothing else is found then it is unique
        {
          std::vector<ea_t> search_result = find_pattern(signature_generator.pat, {true, true, target_ea, last_found_address, false});
          if(search_result.empty())
            break;

          // Update the last found address so we dont have to scan that region anymore
          last_found_address = search_result[0];
        }

        // If result is 2, we already handled iterator advance
        if(result == 2)
          continue;
      }

      if(mnemonic_opcodes != nullptr)
        free(mnemonic_opcodes);
    }

    // Do we have a signature to build?
    if(!signature_generator.has_bytes)
      return "";

    // Don't trim selected-range sigs — user explicitly chose those bytes
    if(!selected_range)
      signature_generator.trim();

    if(!signature_generator.has_bytes)
      return "";

    // Create a render of the signature in the selected style
    sig_core::render_result_t rendered = signature_generator.render(style, make_render_opts());
    if(!rendered.ok){
      hide_wait_box();
      msg("[Fusion] Signature render error: %s\n", rendered.err.c_str());
      return "";
    }

    // Calculate elapsed time
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    double seconds = duration.count() / 1000.0;

    // Auto-validate: search what the user actually gets (the rendered text,
    // re-parsed — catches any clipboard-format ambiguity). Hash styles are not
    // searchable text; validate the underlying pattern instead.
    size_t match_count = 0;
    if(style == SIGNATURE_STYLE_FNV1A || style == SIGNATURE_STYLE_CRC32){
      match_count = find_pattern(signature_generator.pat, {true, false, 0, 0, false}).size();
    }
    else{
      sig_core::parse_result_t roundtrip = sig_core::parse(rendered.out, make_parse_opts());
      match_count = roundtrip.ok ? find_pattern(roundtrip.pat, {true, false, 0, 0, false}).size() : 0;
    }

    if(verbose){
      i8 buffer[8192 + 50];
      if(match_count == 1)
        qsnprintf(buffer, sizeof(buffer), "%s (%.3fs | unique)", rendered.out.c_str(), seconds);
      else if(match_count == 0)
        qsnprintf(buffer, sizeof(buffer), "%s (%.3fs | NO MATCHES)", rendered.out.c_str(), seconds);
      else
        qsnprintf(buffer, sizeof(buffer), "%s (%.3fs | %zu matches)", rendered.out.c_str(), seconds, match_count);

      if(n_settings::data & FLAG_COPY_CREATED_SIGNATURES_TO_CB)
        n_utils::copy_to_clipboard((i8*)rendered.out.c_str());

      msg("[Fusion] %s\n", buffer); // Always print full info to console
      beep(beep_default);
    }

    return rendered.out;
  }

  // snapshot all segments into plain memory so threads can search without IDA API.
  // Validity bitmap tracks initialized bytes — uninitialized regions never match.
  static std::vector<sig_core::mem_section_t> load_memory_image() {
    std::vector<sig_core::mem_section_t> sections;
    int count = get_segm_qty();
    for (int i = 0; i < count; i++) {
      segment_t* seg = getnseg(i);
      if (seg == nullptr) continue;
      sig_core::mem_section_t sec;
      sec.start_ea = seg->start_ea;
      size_t len = (size_t)(seg->end_ea - seg->start_ea);
      sec.bytes.resize(len, 0);
      sec.valid.assign(len, false);
      std::vector<u8> initmask((len + 7) / 8, 0);
      ssize_t got = get_bytes(sec.bytes.data(), (ssize_t)len, seg->start_ea, GMB_READALL, initmask.data());
      if (got > 0) {
        for (size_t k = 0; k < (size_t)got && k < len; k++)
          sec.valid[k] = (initmask[k / 8] & (1 << (k % 8))) != 0;
      }
      sections.push_back(std::move(sec));
    }
    return sections;
  }

  struct pre_insn_t {
    u32             size;
    i32             imm_offset;
    std::vector<u8> raw;
  };

  // decode up to ~150 bytes from start_ea on the main thread and cache the raw bytes
  // threads only see pre_insn_t — no IDA API needed after this point
  static std::vector<pre_insn_t> pre_decode(ea_t start_ea, ea_t ea_max) {
    std::vector<pre_insn_t> insns;
    size_t total_bytes = 0;

    func_item_iterator_t it;
    it.set_range(start_ea, ea_max);

    while (total_bytes < 150) {
      ea_t addr = it.current();

      insn_t insn;
      if (!decode_insn(&insn, addr)) break;

      if (n_settings::data & FLAG_RESPECT_FUNCTION_BOUNDARIES) {
        func_t* f = get_func(addr);
        if (f != nullptr && addr >= f->end_ea) break;
      }

      pre_insn_t pi;
      pi.size       = insn.size;
      pi.imm_offset = n_utils::get_insn_imm_offset(&insn);
      pi.raw.resize(insn.size);
      // Short read => unreliable bytes; stop instead of signing garbage.
      if (get_bytes(pi.raw.data(), (ssize_t)insn.size, addr) != (ssize_t)insn.size) break;
      total_bytes += insn.size;

      // IDA doesn't parse int3/nop correctly in iterators, step over manually
      bool manual_step = (pi.raw[0] == 0xCC || pi.raw[0] == 0x90);
      insns.push_back(std::move(pi));

      if (manual_step)
        it.set_range(addr + 1, ea_max);
      else if (!it.next_not_tail())
        break;
    }

    return insns;
  }

  struct xref_result_t { ea_t caller_ea; std::string sig; };

  // worker: builds the sig byte-by-byte from pre-decoded instructions and checks
  // uniqueness against the memory snapshot — called from threads, zero IDA API usage.
  static bool xref_worker(const std::vector<pre_insn_t>& insns,
                          const std::vector<sig_core::mem_section_t>& mem,
                          ea_t caller_ea, ea_t ea_min,
                          e_signature_style style,
                          sig_core::render_opts_t render_opts,
                          xref_result_t& out) {
    bool use_wildcards = !(n_settings::data & FLAG_DISABLE_WILDCARDS);
    sig_core::builder_t sig_gen;
    ea_t last_found = ea_min;

    for (const auto& pi : insns) {
      // wildcard the immediate operand bytes, keep the rest fixed
      for (u32 k = 0; k < pi.size; k++) {
        bool is_imm = use_wildcards && pi.imm_offset > 0 && (i32)k >= pi.imm_offset;
        sig_gen.add(pi.raw[k], is_imm);
      }

      // skip until we have something worth searching — first instr is usually E8 ?? ?? ?? ??
      if (sig_gen.pat.bytes.size() < 8) continue;

      auto found = sig_core::mem_find(mem, sig_gen.pat, last_found, (u64)caller_ea);
      if (!found.has_value()) {
        // nothing else matches — unique sig found
        sig_gen.trim();
        if (!sig_gen.has_bytes)
          return false;
        sig_core::render_result_t rendered = sig_gen.render(style, render_opts);
        if (!rendered.ok) return false;
        out = { caller_ea, rendered.out };
        return true;
      }

      last_found = (ea_t)*found;
    }
    return false;
  }

  static void create_xref(e_signature_style style) {
    ea_t target_ea = get_screen_ea();

    func_t* func = get_func(target_ea);
    if (func != nullptr) target_ea = func->start_ea;

    replace_wait_box("[Fusion] Collecting XREFs to `0x%llX`...", target_ea);

    // grab all call/jmp xrefs, ignore ordinary flow (fl_F)
    std::vector<ea_t> call_sites;
    xrefblk_t xref;
    for (bool ok = xref.first_to(target_ea, 0); ok; ok = xref.next_to()) {
      if (xref.iscode && xref.type != fl_F)
        call_sites.push_back(xref.from);
    }

    if (call_sites.empty()) {
      u32 data_xref_count = 0;
      xrefblk_t dxref;
      for (bool ok = dxref.first_to(target_ea, XREF_DATA); ok; ok = dxref.next_to())
        data_xref_count++;
      hide_wait_box();
      if (data_xref_count > 0)
        warning("[Fusion] No code XREFs found to `0x%llX`.\n\nFound %u data XREF(s) - this function is likely called through a vtable (virtual dispatch).\n\nSign the vtable entry or a function that calls it directly instead.", target_ea, data_xref_count);
      else
        warning("[Fusion] No XREFs found to `0x%llX`.", target_ea);
      return;
    }

    // drop call sites that aren't inside a real function (dead regions)
    if (!(n_settings::data & FLAG_ALLOW_SIG_CREATION_IN_DR)) {
      call_sites.erase(
        std::remove_if(call_sites.begin(), call_sites.end(),
          [](ea_t ea) { return get_func_num(ea) == 0xFFFFFFFF; }),
        call_sites.end());
    }

    if (call_sites.empty()) {
      hide_wait_box();
      warning("[Fusion] All XREFs to `0x%llX` are in non-function regions.", target_ea);
      return;
    }

    ea_t ea_min = 0, ea_max = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    msg("[Fusion] %zu XREF(s) to 0x%llX, generating signatures...\n", call_sites.size(), target_ea);

    // snapshot all segments (search must judge uniqueness over the same span find() scans)
    replace_wait_box("[Fusion] Loading memory image...");
    auto mem = load_memory_image();

    // decode all call sites on the main thread (IDA API required here)
    struct decoded_site_t { ea_t caller_ea; std::vector<pre_insn_t> insns; };
    std::vector<decoded_site_t> sites;
    sites.reserve(call_sites.size());

    for (size_t i = 0; i < call_sites.size(); i++) {
      if (user_cancelled()) { hide_wait_box(); return; }
      replace_wait_box("[Fusion] Pre-decoding XREF %zu/%zu...", i + 1, call_sites.size());
      sites.push_back({ call_sites[i], pre_decode(call_sites[i], ea_max) });
    }

    // hand off to worker threads — each thread gets a slice of call sites and
    // searches the memory snapshot independently (no IDA API, no shared writes)
    replace_wait_box("[Fusion] Searching (%zu thread(s))...",
      std::max(1u, std::thread::hardware_concurrency()));

    auto overall_start = std::chrono::high_resolution_clock::now();

    std::vector<xref_result_t> results;
    std::mutex results_mutex;

    unsigned int hw = std::max(1u, std::thread::hardware_concurrency());
    size_t n     = sites.size();
    size_t grain = (n + hw - 1) / hw;

    std::vector<std::thread> threads;
    threads.reserve(hw);

    for (size_t t = 0; t < hw; t++) {
      size_t start = t * grain;
      if (start >= n) break;
      size_t end = std::min(start + grain, n);
      threads.emplace_back([&, start, end]() {
        for (size_t i = start; i < end; i++) {
          xref_result_t res;
          if (xref_worker(sites[i].insns, mem, sites[i].caller_ea, ea_min, style,
                          make_render_opts(), res)) {
            std::lock_guard<std::mutex> lock(results_mutex);
            results.push_back(std::move(res));
          }
        }
      });
    }

    for (auto& t : threads) t.join();

    if (results.empty()) {
      hide_wait_box();
      warning("[Fusion] No unique XREF signature could be generated for `0x%llX`.", target_ea);
      return;
    }

    // Re-validate every candidate with the real searcher on the main thread:
    // the printed/copied sig must have exactly one match, at the caller.
    size_t total = results.size();
    std::vector<xref_result_t> verified;
    for (size_t i = 0; i < results.size(); i++) {
      replace_wait_box("[Fusion] Verifying %zu/%zu...", i + 1, results.size());
      sig_core::parse_result_t parsed = sig_core::parse(results[i].sig, make_parse_opts());
      if (!parsed.ok) continue;
      std::vector<ea_t> matches = find_pattern(parsed.pat, {true, false, 0, 0, false});
      if (matches.size() == 1 && matches[0] == results[i].caller_ea)
        verified.push_back(std::move(results[i]));
    }

    if (verified.empty()) {
      hide_wait_box();
      warning("[Fusion] No XREF signature survived uniqueness verification for `0x%llX`.", target_ea);
      return;
    }

    std::sort(verified.begin(), verified.end(), [](const xref_result_t& a, const xref_result_t& b) {
      return a.sig.size() < b.sig.size();
    });

    double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::high_resolution_clock::now() - overall_start).count() / 1000.0;

    for (size_t i = 0; i < verified.size(); i++)
      msg("[Fusion] XREF[%zu] 0x%08llX -> %s (verified unique)\n", i + 1, verified[i].caller_ea, verified[i].sig.c_str());

    msg("[Fusion] Done: %zu/%zu XREF sig(s) verified, shortest first (%.3fs) - shortest copied to clipboard\n",
        verified.size(), total, elapsed);

    if (n_settings::data & FLAG_COPY_CREATED_SIGNATURES_TO_CB)
      n_utils::copy_to_clipboard((i8*)verified[0].sig.c_str());

    beep(beep_default);
  }

  //------------------------------------------------------------------ IDA-coupled selftest
  // V1/V2/V4/V5/V6: validates the IDA-layer invariants against the currently
  // open database. Must run on the main thread inside IDA. Returns failure count.

  static int run_ida_selftest(bool (*log_fn)(const char*)){
    int fails = 0;
    auto check = [&](const char* name, bool ok, const std::string& detail = ""){
      if(!ok){
        fails++;
        std::string line = std::string("[FAIL] ") + name + (detail.empty() ? "" : " | " + detail);
        log_fn(line.c_str());
      }
    };

    log_fn("[Fusion selftest] IDA-coupled checks (V1/V2/V4/V5/V6)");

    ea_t ea_min = 0, ea_max = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    // Sample up to 32 non-trivial functions.
    std::vector<ea_t> funcs;
    int qty = get_func_qty();
    for (int i = 0; i < qty && funcs.size() < 32; i++) {
      func_t* f = getn_func(i);
      if (f == nullptr || f->size() < 16)
        continue;
      funcs.push_back(f->start_ea);
    }
    check("V1 sampled functions exist", !funcs.empty());

    // Helper: create a signature at fea in the given style, then verify the
    // plugin's own searcher finds the generating address with it.
    auto roundtrip = [&](e_signature_style st, ea_t fea) -> bool {
      std::string sig = create(st, fea, false);
      if (sig.empty())
        return false;
      sig_core::parse_result_t p = sig_core::parse(sig, make_parse_opts());
      if (!p.ok)
        return false;
      std::vector<ea_t> res = find_pattern(p.pat, {true, false, 0, 0, false});
      return std::find(res.begin(), res.end(), fea) != res.end();
    };

    // V1: create -> find round-trip, IDA style, on every sampled function.
    for (ea_t fea : funcs)
      check("V1 create->find round-trip (IDA)", roundtrip(SIGNATURE_STYLE_IDA, fea),
            n_utils::format("ea=0x%llX", (u64)fea));

    // V2: CODE style with unicode wildcards, maskless and masked (bug 2 end-to-end).
    {
      u32 saved = n_settings::data;
      n_settings::data |= FLAG_USE_UNICODE_WILDCARD;
      size_t testn = std::min<size_t>(funcs.size(), 4);
      for (size_t i = 0; i < testn; i++)
        check("V2 unicode CODE round-trip (maskless)",
              roundtrip(SIGNATURE_STYLE_CODE, funcs[i]),
              n_utils::format("ea=0x%llX", (u64)funcs[i]));
      n_settings::data |= FLAG_INCLUDE_MASK_FOR_CODE_SIGS;
      for (size_t i = 0; i < testn; i++)
        check("V2 unicode CODE round-trip (masked)",
              roundtrip(SIGNATURE_STYLE_CODE, funcs[i]),
              n_utils::format("ea=0x%llX", (u64)funcs[i]));
      n_settings::data = saved;
    }

    // V4: SDK assumption — bin_search honors BIN_SEARCH_BITMASK|BIN_SEARCH_CASE
    // with nibble masks. Pattern is built FROM the bytes at `probe`, so a search
    // starting at `probe` must return `probe` itself.
    {
      ea_t probe = funcs.empty() ? ea_min : funcs[0];
      u8 buf[4];
      bool ok = get_bytes(buf, 4, probe) == 4;
      if (ok) {
        sig_core::pattern_t p;
        const u8 masks[4] = {0xFF, 0xF0, 0x0F, 0xFF};
        for (int k = 0; k < 4; k++) {
          p.bytes.push_back(buf[k]);
          p.mask.push_back(masks[k]);
        }
        compiled_binpat_vec_t data;
        compile_pattern(p, &data);
        ea_t hit = bin_search(probe, ea_max, data,
                              BIN_SEARCH_FORWARD | BIN_SEARCH_CASE | BIN_SEARCH_BITMASK);
        ok = (hit == probe);
      }
      check("V4 bin_search BITMASK|CASE honored (nibble mask)", ok);
    }

    // V5: SDK assumption — get_bytes init-mask bit polarity matches is_loaded().
    {
      ea_t probe = funcs.empty() ? ea_min : funcs[0];
      u8 buf[32];
      u8 mask[(32 + 7) / 8];
      ssize_t got = get_bytes(buf, 32, probe, GMB_READALL, mask);
      bool ok = got > 0;
      for (ssize_t k = 0; ok && k < got; k++) {
        bool bit = (mask[k / 8] & (1 << (k % 8))) != 0;
        if (bit != is_loaded(probe + k))
          ok = false;
      }
      check("V5 get_bytes init-mask polarity == is_loaded", ok);
    }

    // V6: snapshot scanner results are a subset of find() results (bug 4 invariant).
    {
      std::vector<sig_core::mem_section_t> snap = load_memory_image();
      size_t testn = std::min<size_t>(funcs.size(), 4);
      for (size_t i = 0; i < testn; i++) {
        ea_t fea = funcs[i];
        std::string sig = create(SIGNATURE_STYLE_IDA, fea, false);
        bool ok = !sig.empty();
        if (ok) {
          sig_core::parse_result_t p = sig_core::parse(sig, make_parse_opts());
          ok = p.ok;
          if (ok) {
            std::vector<u64> snap_hits = sig_core::mem_find_all(snap, p.pat, 0, (u64)BADADDR);
            std::vector<ea_t> find_hits = find_pattern(p.pat, {true, false, 0, 0, false});
            for (u64 h : snap_hits) {
              if (std::find(find_hits.begin(), find_hits.end(), (ea_t)h) == find_hits.end()) {
                ok = false;
                break;
              }
            }
          }
        }
        check("V6 snapshot results subset of find results", ok,
              n_utils::format("ea=0x%llX", (u64)fea));
      }
    }

    return fails;
  }

}; // namespace n_signature
