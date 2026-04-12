#pragma once

#include <cstdio>
#include <cstring>
#include <string>
#include <chrono>
#include <algorithm>
#ifdef __NT__
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
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
#include <xref.hpp>
#include <segment.hpp>
#include <thread>
#include <mutex>

// Custom
#include "n_utils.h"
#include "n_settings.h"
#include "n_signature.h"
