#pragma once

// Include our signature generator
#include "c_signature_generator.h"

struct s_signature_find_settings{
  bool silent             = true;   // Output information
  bool stop_at_first      = false;  // Stop at first found signature
  ea_t ignore_addr        = 0;      // Ignore a selected address
  ea_t start_at_addr      = 0;      // Start scanning from an address
  bool jump_to_found_addr = false;  // Jump to the found address
};

namespace n_signature{
  static std::vector<ea_t> find(std::string signature, s_signature_find_settings find_settings){
    std::vector<ea_t> ea;

    // Handle the conversion of a code style sig to an IDA one if required
    if(strstr(signature.c_str(), "\\x")){
      // Firstly, convert \x to a space
      signature = std::regex_replace(signature, std::regex("\\\\x"), " ");

      // Remove any masks before converting 00's to a ?
      signature = std::regex_replace(signature, std::regex("x"), "");
      signature = std::regex_replace(signature, std::regex("\\?"), "");

      // Convert any 00's to ?
      signature = std::regex_replace(signature, std::regex("00"), "?");

      // Remove first space if there is one
      if(!signature.empty() && signature[0] == ' ')
        signature.erase(0, 1);
    }

    if(!find_settings.silent){
      hide_wait_box();
      show_wait_box("[Fusion] Searching...");
    }

    ea_t ea_min = 0;
    ea_t ea_max = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    ea_t addr = (find_settings.start_at_addr > 0 ? find_settings.start_at_addr : ea_min) - 1;

#if IDA_SDK_VERSION >= 900
    compiled_binpat_vec_t sig_data{};
    parse_binpat_str(&sig_data, addr, signature.c_str(), 16);
#endif

    while(true){
#if IDA_SDK_VERSION >= 900
      // IDA 9.x uses bin_search (bin_search3 was renamed)
      addr = bin_search(addr + 1, ea_max, sig_data, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD);
#else
      addr = find_binary(addr + 1, ea_max, signature.c_str(), 16, SEARCH_DOWN);
#endif

      if(addr == 0 || addr == BADADDR)
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

  // Helper function to process instruction and add to signature
  // Returns: 0 = break, 1 = continue with next_not_tail, 2 = continue without next_not_tail
  static i32 process_instruction(ea_t addr, c_signature_generator& signature_generator, func_item_iterator_t& iterator, ea_t ea_max, insn_t* out_insn = nullptr){
    insn_t insn;
    if(!decode_insn(&insn, addr))
      return 0;

    // Check if we've reached a function boundary (if enabled)
    if(n_settings::data & FLAG_RESPECT_FUNCTION_BOUNDARIES){
      func_t* func = get_func(addr);
      if(func != nullptr && addr >= func->end_ea)
        return 0; // Don't go past function end
    }

    // Get the imm offset for this instruction
    i32 imm_offset = n_utils::get_insn_imm_offset(&insn);

    // Check if wildcards are enabled
    bool use_wildcards = !(n_settings::data & FLAG_DISABLE_WILDCARDS);

    // Now add the bytes to the signature generator
    for(ea_t op_addr = addr; op_addr < (addr + insn.size); op_addr++)
      signature_generator.add(get_byte(op_addr), use_wildcards && imm_offset > 0 && (op_addr - addr) >= imm_offset);

    // Return instruction if requested
    if(out_insn != nullptr)
      *out_insn = insn;

    // These instructions are not parsed correctly by ida, so lets fix it
    if(get_byte(addr) == 0xCC || get_byte(addr) == 0x90){
      iterator.set_range(addr + 1, ea_max);
      return 2; // Continue but skip next_not_tail
    }

    return iterator.next_not_tail() ? 1 : 0;
  }

  static void create(e_signature_style style){
    if(!(n_settings::data & FLAG_ALLOW_SIG_CREATION_IN_DR) && get_func_num(get_screen_ea()) == 0xFFFFFFFF){
      hide_wait_box();
      warning("[Fusion] `0x%llX` Is not in a valid assembly region.\n\nHint: You can disable this in the settings of Fusion.", get_screen_ea());
      return;
    }

    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();

    c_signature_generator signature_generator;
    ea_t                  ea_region_start = 0;
    ea_t                  ea_region_end   = 0;
    ea_t                  ea_min          = 0;
    ea_t                  ea_max          = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    // Display a status that we are creating a signature for our screen ea
    replace_wait_box("[Fusion] Creating signature for `0x%llX`", get_screen_ea());

    // If we have selected a range of assembly code, sig exactly those bytes (no trim — user chose them)
    bool selected_range = (n_settings::data & FLAG_COPY_SELECTED_BYTES_ONLY_IN_RANGE)
                          && read_range_selection(nullptr, &ea_region_start, &ea_region_end)
                          && ea_region_end > ea_region_start;
    if(selected_range){
      func_item_iterator_t iterator;
      iterator.set_range(ea_region_start, ea_region_end);
      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        if(process_instruction(addr, signature_generator, iterator, ea_max) == 0)
          break;
      }
    }
    else{
      ea_t target_addr        = get_screen_ea();
      ea_t last_found_address = ea_min;

      // Generate memory for the mnemonic opcodes list
      u32 mnemonic_opcodes_len  = 5000/*~4.9KB*/;
      i8* mnemonic_opcodes      = (n_settings::data & FLAG_SHOW_MNEMONIC_OPCODES_SIGGED) ? (i8*)malloc(mnemonic_opcodes_len) : nullptr;

      if(mnemonic_opcodes != nullptr)
        memset(mnemonic_opcodes, 0, mnemonic_opcodes_len);

      func_item_iterator_t iterator;
      iterator.set_range(target_addr, ea_max);
      for(ea_t addr = iterator.current(); true; addr = iterator.current()){
        insn_t insn;
        i32 result = process_instruction(addr, signature_generator, iterator, ea_max, &insn);
        if(result == 0)
          break;

        // Add details on whats going on in relation to this creation
        if(n_settings::data & FLAG_SHOW_MNEMONIC_OPCODES_SIGGED){
          qsnprintf(mnemonic_opcodes + strlen(mnemonic_opcodes), mnemonic_opcodes_len - strlen(mnemonic_opcodes), "+ %s\n", insn.get_canon_mnem(PH));
          replace_wait_box("[Fusion] Creating signature for `0x%llX`\n\n%s", target_addr, mnemonic_opcodes);
        }

        // Attempt to search for this signature, if nothing is found then we have a unique signature
        {
          i8* ida_sig = signature_generator.render(SIGNATURE_STYLE_IDA);
          if(ida_sig == nullptr){
            error("[Fusion] fatal error rendering signature (1)\n");
            break;
          }

          std::vector<ea_t> search_result = find(ida_sig, {true, true, target_addr, last_found_address, false});
          free(ida_sig);
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
    if(signature_generator.has_bytes){
      // Don't trim selected-range sigs — user explicitly chose those bytes
      if(!selected_range)
        signature_generator.trim();

      // Create a render of the signature in the selected style
      i8* signature = signature_generator.render(style);

      if(signature == nullptr){
        error("[Fusion] fatal error rendering signature (2)\n");
        return;
      }

      // Calculate elapsed time
      auto end_time = std::chrono::high_resolution_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
      double seconds = duration.count() / 1000.0;

      // Auto-validate: Check signature uniqueness
      std::vector<ea_t> validation_results = find(signature, {true, false, 0, 0, false});
      size_t match_count = validation_results.size();

      // Create signature with timing info and match count for console display
      i8 buffer[8192 + 50];
      if(match_count == 1)
        qsnprintf(buffer, sizeof(buffer), "%s (%.3fs | unique)", signature, seconds);
      else if(match_count == 0)
        qsnprintf(buffer, sizeof(buffer), "%s (%.3fs | NO MATCHES)", signature, seconds);
      else
        qsnprintf(buffer, sizeof(buffer), "%s (%.3fs | %zu matches)", signature, seconds, match_count);

      // Copy ONLY signature to clipboard (without timing/matches), and always print to console
      if(n_settings::data & FLAG_COPY_CREATED_SIGNATURES_TO_CB)
        n_utils::copy_to_clipboard(signature);

      msg("[Fusion] %s\n", buffer); // Always print full info to console

      // Now free the rendered signature
      free(signature);

      beep(beep_default);
    }
  }

  static void create_xref(e_signature_style style) {
    ea_t target_ea = get_screen_ea();

    // Prefer function start for XREF lookup when inside a function
    func_t* func = get_func(target_ea);
    if (func != nullptr)
      target_ea = func->start_ea;

    replace_wait_box("[Fusion] Collecting XREFs to `0x%llX`...", target_ea);

    // Collect all code XREFs (calls + jumps, skip ordinary flow)
    std::vector<ea_t> call_sites;
    xrefblk_t xref;
    for (bool ok = xref.first_to(target_ea, 0); ok; ok = xref.next_to()) {
      if (xref.iscode && xref.type != fl_F)
        call_sites.push_back(xref.from);
    }

    if (call_sites.empty()) {
      // Count data XREFs as a hint (virtual dispatch / vtable functions have data refs only)
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

    ea_t ea_min = 0, ea_max = 0;
    n_utils::get_text_min_max(ea_min, ea_max);

    msg("[Fusion] %zu XREF(s) to 0x%llX, generating signatures...\n", call_sites.size(), target_ea);

    struct xref_result_t { ea_t caller_ea; std::string sig; };
    std::vector<xref_result_t> results;
    auto overall_start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < call_sites.size(); i++) {
      ea_t caller_ea = call_sites[i];
      replace_wait_box("[Fusion] XREF %zu/%zu (0x%llX)...", i + 1, call_sites.size(), caller_ea);

      if (!(n_settings::data & FLAG_ALLOW_SIG_CREATION_IN_DR) && get_func_num(caller_ea) == 0xFFFFFFFF)
        continue;

      c_signature_generator sig_gen;
      ea_t last_found = ea_min;
      func_item_iterator_t iterator;
      iterator.set_range(caller_ea, ea_max);

      for (ea_t addr = iterator.current(); true; addr = iterator.current()) {
        i32 result = process_instruction(addr, sig_gen, iterator, ea_max);
        if (result == 0)
          break;

        // Skip search until we have enough bytes (first call instr is always E8 ?? ?? ?? ??)
        // and bail out if the sig grows too large without becoming unique (random optimization)
        size_t byte_count = sig_gen.bytes.size();
        if (byte_count < 8) { if (result == 2) continue; continue; }
        if (byte_count > 100) break;

        i8* ida_sig = sig_gen.render(SIGNATURE_STYLE_IDA);
        if (ida_sig == nullptr)
          break;

        std::vector<ea_t> search_result = find(ida_sig, {true, true, caller_ea, last_found, false});
        free(ida_sig);

        if (search_result.empty()) {
          sig_gen.trim();
          i8* signature = sig_gen.render(style);
          if (signature != nullptr) {
            results.push_back({caller_ea, std::string(signature)});
            free(signature);
          }
          break;
        }

        last_found = search_result[0];
        if (result == 2)
          continue;
      }
    }

    if (results.empty()) {
      hide_wait_box();
      warning("[Fusion] No unique XREF signature could be generated for `0x%llX`.", target_ea);
      return;
    }

    // Sort by sig length (shortest first, like ida-sigmaker)
    std::sort(results.begin(), results.end(), [](const xref_result_t& a, const xref_result_t& b){
      return a.sig.size() < b.sig.size();
    });

    double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::high_resolution_clock::now() - overall_start).count() / 1000.0;

    for (size_t i = 0; i < results.size(); i++)
      msg("[Fusion] XREF[%zu] 0x%08llX -> %s\n", i + 1, results[i].caller_ea, results[i].sig.c_str());

    msg("[Fusion] Done: %zu XREF sig(s), shortest first (%.3fs) - shortest copied to clipboard\n", results.size(), elapsed);

    // Copy shortest (first after sort) to clipboard
    if (n_settings::data & FLAG_COPY_CREATED_SIGNATURES_TO_CB)
      n_utils::copy_to_clipboard((i8*)results[0].sig.c_str());

    beep(beep_default);
  }
};