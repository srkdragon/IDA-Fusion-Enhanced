#include "link.h"

// Forward declarations
static ssize_t idaapi ui_notification(void *, int notification_code, va_list va);

// Global plugin dialog function
EXTERN bool idaapi plugin_run(size_t arg){
    std::string form_str = n_utils::format(
      "IDA-Fusion for %.1f+\n"
      "<#Generate signature (CODE Style):R>\n"
      "<#Generate signature (IDA Style):R>\n"
      "<#Generate signature (CRC-32 Style):R>\n"
      "<#Generate signature (FNV1-A Style):R>\n"
      "<#Search for a signature (CODE/IDA):R>\n"
      "<#Configure settings:R>>\n"
      "\n"
      "<#Use wildcards for immediate values:C>\n"
      "<#Respect function boundaries:C>>\n", (float)IDA_SDK_VERSION / 100.f
    ).c_str();

    // Load last choice from settings
    static i32  choice  = (n_settings::data >> CHOICE_SHIFT) & CHOICE_MASK;
    static u32  use_wildcards = 1; // Default: enabled
    static u32  respect_boundaries = 1; // Default: enabled
    bool        form_ok = ask_form(form_str.c_str(), &choice, &use_wildcards, &respect_boundaries);

    if(!form_ok)
      return true;

    // Save last choice to settings
    n_settings::data = (n_settings::data & ~(CHOICE_MASK << CHOICE_SHIFT)) | ((choice & CHOICE_MASK) << CHOICE_SHIFT);

    // Update wildcard flag based on checkbox
    if(use_wildcards)
      n_settings::data &= ~FLAG_DISABLE_WILDCARDS; // Enable wildcards (clear flag)
    else
      n_settings::data |= FLAG_DISABLE_WILDCARDS;  // Disable wildcards (set flag)

    // Update function boundary flag based on checkbox
    if(respect_boundaries)
      n_settings::data |= FLAG_RESPECT_FUNCTION_BOUNDARIES; // Enable boundaries (set flag)
    else
      n_settings::data &= ~FLAG_RESPECT_FUNCTION_BOUNDARIES; // Disable boundaries (clear flag)

    // Save settings after checkbox changes
    n_settings::save_settings();

    switch(choice){
      case 0:{
        show_wait_box("[Fusion] Creating CODE signature...");
        n_signature::create(SIGNATURE_STYLE_CODE);
        hide_wait_box();
        break;
      }
      case 1:{
        show_wait_box("[Fusion] Creating IDA signature...");
        n_signature::create(SIGNATURE_STYLE_IDA);
        hide_wait_box();
        break;
      }
      case 2:{
        show_wait_box("[Fusion] Creating CRC-32 signature...");
        n_signature::create(SIGNATURE_STYLE_CRC32);
        hide_wait_box();
        break;
      }
      case 3:{
        show_wait_box("[Fusion] Creating FNV-1A signature...");
        n_signature::create(SIGNATURE_STYLE_FNV1A);
        hide_wait_box();
        break;
      }
      case 4:{
        static i8 signature_to_find[8192];
        if(!ask_form(
          "Fusion — Enter CODE/IDA signature\n"
          "<Signature:A5:8192:100>"
        , &signature_to_find))
          break;

        n_signature::find(signature_to_find, {false, (bool)(n_settings::data & FLAG_STOP_AT_FIRST_SIGNATURE_FOUND), 0, 0, static_cast<bool>(n_settings::data & FLAG_AUTO_JUMP_TO_FOUND_SIGNATURES)});
        break;
      }
      case 5:{
        n_settings::show_settings_dialog();
        break;
      }
    }

    return true;
}

// Action handler for context menu - opens main dialog
struct fusion_dialog_action_handler_t : public action_handler_t {
  virtual int idaapi activate(action_activation_ctx_t *ctx) override {
    // Call the main plugin dialog (same as Edit → Plugins → Fusion)
    plugin_run(0);
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx) override {
    return AST_ENABLE_ALWAYS;
  }
};

// Global action handler
static fusion_dialog_action_handler_t ah_dialog;

// Plugin module class for IDA 9.x
struct fusion_plugin_ctx_t : public plugmod_t {
  virtual bool idaapi run(size_t arg) override {
    return plugin_run(arg);
  }

  virtual ~fusion_plugin_ctx_t() {
    // Unregister action
    unregister_action("fusion:main");

    // Unhook UI notifications
    unhook_from_notification_point(HT_UI, ui_notification, nullptr);
  }
};

// UI notification hook for adding context menu
static ssize_t idaapi ui_notification(void *, int notification_code, va_list va) {
  if (notification_code == ui_finish_populating_widget_popup) {
    TWidget *widget = va_arg(va, TWidget *);
    TPopupMenu *popup = va_arg(va, TPopupMenu *);

    // Show context menu in both disassembly and pseudocode windows
    if (get_widget_type(widget) == BWN_DISASM || get_widget_type(widget) == BWN_PSEUDOCODE) {
      // Add separator
      attach_action_to_popup(widget, popup, "-", nullptr, SETMENU_APP);

      // Add Fusion item directly to root menu (not in submenu)
      attach_action_to_popup(widget, popup, "fusion:main", nullptr, SETMENU_APP);
    }
  }
  return 0;
}

plugmod_t* idaapi plugin_init(void){
  // Load saved settings
  n_settings::load_settings();

  // Register single action for context menu
  action_desc_t desc_main = ACTION_DESC_LITERAL(
    "fusion:main",
    "Fusion",
    &ah_dialog,
#ifdef __MAC__
    "Cmd+Option+S",   // macOS: Command + Option keys
#else
    "Ctrl+Alt+S",     // Windows/Linux: Ctrl + Alt keys
#endif
    "Open Fusion signature generator dialog",
    -1
  );

  register_action(desc_main);

  // Hook UI notifications for popup menu
  hook_to_notification_point(HT_UI, ui_notification, nullptr);

  return new fusion_plugin_ctx_t;
}

EXTERN plugin_t PLUGIN = {
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,  // Changed from PLUGIN_PROC to support plugmod_t
  plugin_init,
  nullptr,
  nullptr,       // run is handled by plugmod_t
  "ULTRA Fast Signature scanner & creator for IDA9+",
  "https://github.com/K4ryuu/IDA-Fusion",
  "Fusion",
#ifdef __MAC__
  "Cmd-Option-S"    // macOS: Command + Option keys
#else
  "Ctrl-Alt-S"      // Windows/Linux: Ctrl + Alt keys
#endif
};
