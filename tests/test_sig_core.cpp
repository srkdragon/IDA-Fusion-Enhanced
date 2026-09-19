// Standalone sig_core proof harness — no IDA SDK required.
// Exit code = number of failed checks (0 = everything proven).
// Optional: --fuzz N to raise the round-trip trial count for deep local runs.

#include "../src/sig_core_selftest.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

static bool log_line(const char* line){
  std::printf("%s\n", line);
  return true;
}

int main(int argc, char** argv){
  int trials = 1000;
  for (int i = 1; i < argc - 1; i++) {
    if (std::strcmp(argv[i], "--fuzz") == 0)
      trials = std::atoi(argv[i + 1]);
  }
  return sig_selftest::run(log_line, trials);
}
