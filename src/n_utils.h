#pragma once

namespace n_utils{
  inline i32 get_insn_imm_offset(insn_t* insn){
    for(u32 i = 0; i < UA_MAXOP; i++){
      op_t* op = &insn->ops[i];

      // Instruction contains invalid operand/opcode
      if(op->type == o_void)
        return 0;

      // Instruction contains relocated address
      if(op->offb > 0)
        return op->offb;
    }

    return 0;
  }

  inline void get_text_min_max(ea_t& ea_min, ea_t& ea_max){
    ea_min = inf_get_min_ea();
    ea_max = inf_get_max_ea();
  }

  inline void copy_to_clipboard(i8* buffer){
#ifdef __NT__
    // Windows clipboard
    u32   alloc_len = strlen(buffer) + 1;
    void* alloc     = GlobalAlloc(GMEM_FIXED, alloc_len);
    if(alloc == nullptr){
      msg("[Fusion] Failed to allocate clipboard memory\n");
      msg("[Fusion] Signature: %s\n", buffer);
      return;
    }
    qstrncpy((i8*)alloc, buffer, alloc_len);

    OpenClipboard(nullptr);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, alloc);
    CloseClipboard();
#elif defined(__MAC__)
    // macOS clipboard using pbcopy
    #undef fprintf
    FILE* pipe = popen("pbcopy", "w");
    if(pipe){
      fprintf(pipe, "%s", buffer);
      pclose(pipe);
    }
#elif defined(__LINUX__)
    // Linux clipboard using xclip (if available)
    #undef fprintf
    FILE* pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
    if(pipe){
      fprintf(pipe, "%s", buffer);
      pclose(pipe);
    }
#endif
  }

  inline std::string format(const i8* fmt, ...) {
    i8 buffer[1024];

    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    return std::string(buffer);
  }
};