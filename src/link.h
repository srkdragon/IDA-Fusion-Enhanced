#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <chrono>
#ifdef __NT__
#include <windows.h>
#endif
#include <regex>

// Include typedefs
#include "typedefs.h"

// IDA sdk specific
// __NT__, __MAC__, __LINUX__ are defined in makefile
#define __X64__
#include <loader.hpp>
#include <idp.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>

// Custom
#include "n_utils.h"
#include "n_settings.h"
#include "n_signature.h"