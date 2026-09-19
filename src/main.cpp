#include "link.h"
#include "sig_core_selftest.h"

enum e_plugin_action {
  PLUGIN_ACTION_CREATE_CODE_SIGNATURE = 0,
  PLUGIN_ACTION_CREATE_IDA_SIGNATURE = 1,
  PLUGIN_ACTION_CREATE_CRC32_SIGNATURE = 2,
  PLUGIN_ACTION_CREATE_FNV1A_SIGNATURE = 3,
  PLUGIN_ACTION_CREATE_XREF_SIGNATURES = 4,
  PLUGIN_ACTION_CONFIGURE_SETTINGS = 5,
  PLUGIN_ACTION_SEARCH_SIGNATURE = 6,
};

// Global plugin dialog function
EXTERN bool idaapi plugin_run(size_t arg){
    std::string form_str = n_utils::format(
      "IDA-Fusion for %.1f+\n"
      "<#Generate signature (CODE Style):R>\n"
      "<#Generate signature (IDA Style):R>\n"
      "<#Generate signature (CRC-32 Style):R>\n"
      "<#Generate signature (FNV1-A Style):R>\n"
      "<#Generate XREF signatures (IDA Style):R>\n"
      "<#Configure settings:R>\n"
      "<#Search for a signature (CODE/IDA):R>>\n"
      "\n"
      "<#Use wildcards for immediate values:C>\n"
      "<#Respect function boundaries:C>>\n", (float)IDA_SDK_VERSION / 100.f
    ).c_str();

    // Load dialog state from the persisted settings on every invocation,
    // so the checkboxes always reflect what was saved (never silently revert).
    i32  choice             = (n_settings::data >> CHOICE_SHIFT) & CHOICE_MASK;
    u32  use_wildcards      = (n_settings::data & FLAG_DISABLE_WILDCARDS) ? 0 : 1;
    u32  respect_boundaries = (n_settings::data & FLAG_RESPECT_FUNCTION_BOUNDARIES) ? 1 : 0;

    if(choice < PLUGIN_ACTION_CREATE_CODE_SIGNATURE || choice > PLUGIN_ACTION_SEARCH_SIGNATURE)
      choice = PLUGIN_ACTION_CREATE_CODE_SIGNATURE;

    bool        form_ok = ask_form(form_str.c_str(), &choice, &use_wildcards, &respect_boundaries);

    if(!form_ok)
      return true;

    // Save last choice to settings
    n_settings::data = (n_settings::data & ~(CHOICE_MASK << CHOICE_SHIFT)) | ((choice & CHOICE_MASK) << CHOICE_SHIFT);

    // Update wildcard flag based on checkbox
    if(use_wildcards)
      n_settings::data &= ~FLAG_DISABLE_WILDCARDS;
    else
      n_settings::data |= FLAG_DISABLE_WILDCARDS;

    // Update function boundary flag based on checkbox
    if(respect_boundaries)
      n_settings::data |= FLAG_RESPECT_FUNCTION_BOUNDARIES;
    else
      n_settings::data &= ~FLAG_RESPECT_FUNCTION_BOUNDARIES;

    n_settings::save_settings();

    switch(choice){
      case PLUGIN_ACTION_CREATE_CODE_SIGNATURE:{
        show_wait_box("[Fusion] Creating CODE signature...");
        n_signature::create(SIGNATURE_STYLE_CODE);
        hide_wait_box();
        break;
      }
      case PLUGIN_ACTION_CREATE_IDA_SIGNATURE:{
        show_wait_box("[Fusion] Creating IDA signature...");
        n_signature::create(SIGNATURE_STYLE_IDA);
        hide_wait_box();
        break;
      }
      case PLUGIN_ACTION_CREATE_CRC32_SIGNATURE:{
        show_wait_box("[Fusion] Creating CRC-32 signature...");
        n_signature::create(SIGNATURE_STYLE_CRC32);
        hide_wait_box();
        break;
      }
      case PLUGIN_ACTION_CREATE_FNV1A_SIGNATURE:{
        show_wait_box("[Fusion] Creating FNV-1A signature...");
        n_signature::create(SIGNATURE_STYLE_FNV1A);
        hide_wait_box();
        break;
      }
      case PLUGIN_ACTION_CREATE_XREF_SIGNATURES:{
        show_wait_box("[Fusion] Finding XREFs...");
        n_signature::create_xref(SIGNATURE_STYLE_IDA);
        hide_wait_box();
        break;
      }
      case PLUGIN_ACTION_CONFIGURE_SETTINGS:{
        n_settings::show_settings_dialog();
        break;
      }
      case PLUGIN_ACTION_SEARCH_SIGNATURE:{
        static i8 signature_to_find[8192] = {};
        const std::string search_form = n_utils::format(
          "Fusion - Enter CODE/IDA signature\n"
          "<Signature:A5:%zu:100>",
          sizeof(signature_to_find)
        );
        if(!ask_form(search_form.c_str(), signature_to_find))
          break;

        const bool stop_at_first = (n_settings::data & FLAG_STOP_AT_FIRST_SIGNATURE_FOUND) != 0;
        const bool jump_to_found_addr = (n_settings::data & FLAG_AUTO_JUMP_TO_FOUND_SIGNATURES) != 0;
        n_signature::find(signature_to_find, {false, stop_at_first, 0, 0, jump_to_found_addr});
        break;
      }
    }

    return true;
}

// Action handler for context menu
struct fusion_dialog_action_handler_t : public action_handler_t {
  virtual int idaapi activate(action_activation_ctx_t *ctx) override {
    plugin_run(0);
    return 1;
  }
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override {
    return AST_ENABLE_ALWAYS;
  }
};

static fusion_dialog_action_handler_t ah_dialog;

// UI event listener for context menu integration (IDA 9.x modern API)
DECLARE_LISTENER(fusion_ui_listener_t, struct fusion_plugin_ctx_t, ctx);

struct fusion_plugin_ctx_t : public plugmod_t {
  fusion_ui_listener_t ui_listener = fusion_ui_listener_t(*this);

  virtual bool idaapi run(size_t arg) override {
    return plugin_run(arg);
  }

  virtual ~fusion_plugin_ctx_t() {
    unhook_event_listener(HT_UI, &ui_listener);
    unregister_action("fusion:main");
  }
};

ssize_t idaapi fusion_ui_listener_t::on_event(ssize_t notification_code, va_list va) {
  if (notification_code == ui_finish_populating_widget_popup) {
    TWidget *widget = va_arg(va, TWidget *);
    TPopupMenu *popup = va_arg(va, TPopupMenu *);
    if (get_widget_type(widget) == BWN_DISASM || get_widget_type(widget) == BWN_PSEUDOCODE) {
      attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);
      attach_action_to_popup(widget, popup, "fusion:main", nullptr, SETMENU_APP);
    }
  }
  return 0;
}

// Exported self-test. Run from IDAPython inside IDA with a database open:
//   import ctypes; ctypes.CDLL(r"<idadir>\plugins\fusion64-windows-x64.dll").fusion_selftest()
// Returns the number of failed checks (0 = PASS); details go to the Output window.
static bool selftest_log(const char* line){
  msg("%s\n", line);
  return true;
}

EXTERN __declspec(dllexport) int fusion_selftest(){
  u32 saved_settings = n_settings::data;
  n_settings::data &= ~(FLAG_COPY_CREATED_SIGNATURES_TO_CB
                        | FLAG_SHOW_MNEMONIC_OPCODES_SIGGED
                        | FLAG_AUTO_JUMP_TO_FOUND_SIGNATURES);

  show_wait_box("[Fusion] Running self-test...");

  int failures = sig_selftest::run(selftest_log, 300)
               + n_signature::run_ida_selftest(selftest_log);

  hide_wait_box();
  n_settings::data = saved_settings;

  msg("[Fusion] SELFTEST %s - %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
  return failures;
}

plugmod_t* idaapi plugin_init(void){
  n_settings::load_settings();

#ifdef __MAC__
  constexpr const char* fusion_hotkey = "Cmd+Option+S";
#else
  constexpr const char* fusion_hotkey = "Ctrl+Alt+S";
#endif

  action_desc_t desc_main = ACTION_DESC_LITERAL(
    "fusion:main",
    "Fusion",
    &ah_dialog,
    fusion_hotkey,
    "Open Fusion signature generator dialog",
    -1
  );
  register_action(desc_main);

  auto *ctx = new fusion_plugin_ctx_t;
  hook_event_listener(HT_UI, &ctx->ui_listener, ctx);
  return ctx;
}

plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  plugin_init,
  nullptr,
  nullptr,
  "ULTRA Fast Signature scanner & creator for IDA9+",
  "https://github.com/K4ryuu/IDA-Fusion",
  "Fusion",
#ifdef __MAC__
  "Cmd-Option-S"
#else
  "Ctrl-Alt-S"
#endif
};
