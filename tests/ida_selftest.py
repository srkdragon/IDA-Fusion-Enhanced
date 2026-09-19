"""In-IDA proof for the Fusion plugin (Tier B/C of the verification protocol).

Prerequisites:
  - Build the plugin (GitHub Action "Build Windows x64" artifact, or locally)
  - Copy fusion64-windows-x64.dll into <idadir>/plugins/ (or the user plugins dir)
  - Open a real database in IDA 9.x (ideally a PE with .text + data segments
    and 0xCC padding between functions)

Usage (IDA Python console):
    import sys; sys.path.insert(0, r"<repo>\tests")
    import ida_selftest
    ida_selftest.run()

Or the equivalent one-liner:
    import ctypes
    h = ctypes.CDLL(r"<idadir>\plugins\fusion64-windows-x64.dll")
    print("failures:", h.fusion_selftest())

What the DLL export proves (details printed to the Output window):
  Pure core suite (same code the CI runs on every push):
    - parser/renderer golden units (all 4 signature styles)
    - randomized generate -> parse -> search round-trip property proofs
      against an independent brute-force oracle
    - memory-scanner units (section bounds, invalid bytes, ignore/start-at)
    - trim match-set invariance
  IDA-coupled checks against the open database:
    V1  create -> find round-trip on up to 32 sampled functions
    V2  CODE-style unicode-wildcard round-trips (maskless and masked)
    V4  SDK assumption: bin_search honors BIN_SEARCH_BITMASK | BIN_SEARCH_CASE
    V5  SDK assumption: get_bytes init-mask bit polarity == is_loaded()
    V6  memory-snapshot scan results are a subset of find() results

Manual checklist (Tier C — not automatable from a script):
  [ ] Select a range that spans a function end into 0xCC padding and create a
      signature: it must cover exactly the selection (search it back; first
      match at the selection start, byte count == selection size).
  [ ] Settings: disable wildcards -> OK -> reopen the dialog: the checkbox
      must stay unchecked (persisted settings are honored).
  [ ] Generate a CODE sig with mask at a `cmp eax, 0` (83 F8 00): searching it
      must NOT return `cmp eax, 5` (83 F8 05) sites.
  [ ] Paste a malformed signature in the search dialog: an explicit parse
      error must be reported (not a silent "no addresses found").
"""

import ctypes
import os


def _candidate_paths():
    paths = []
    try:  # user plugins dir
        import ida_diskio
        user_dir = ida_diskio.get_user_idadir()
        if user_dir:
            paths.append(os.path.join(user_dir, "plugins", "fusion64-windows-x64.dll"))
    except Exception:
        pass
    try:  # idadir plugins
        from ida_pro import idadir
        paths.append(os.path.join(idadir, "plugins", "fusion64-windows-x64.dll"))
    except Exception:
        pass
    paths.append(os.path.join(os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                              "IDA Pro 9.4", "plugins", "fusion64-windows-x64.dll"))
    return paths


def _find_plugin():
    for p in _candidate_paths():
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        "fusion64-windows-x64.dll not found in: " + "; ".join(_candidate_paths())
        + " — pass the path explicitly: ida_selftest.run(r'...\\fusion64-windows-x64.dll')")


def run(plugin_path=None):
    """Runs fusion_selftest() from the installed plugin DLL (already loaded by
    IDA — LoadLibrary just increments its refcount). Returns the failure count."""
    if plugin_path is None:
        plugin_path = _find_plugin()
    print("[ida_selftest] loading %s" % plugin_path)
    dll = ctypes.CDLL(plugin_path)
    failures = dll.fusion_selftest()
    print("[ida_selftest] fusion_selftest -> %d failure(s) [%s]"
          % (failures, "PASS" if failures == 0 else "FAIL"))
    print("[ida_selftest] full details are in the Output window above")
    return failures


if __name__ == "__main__":
    run()
