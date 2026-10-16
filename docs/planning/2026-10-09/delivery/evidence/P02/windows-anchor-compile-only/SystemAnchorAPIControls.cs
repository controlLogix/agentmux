// Compile-only caller controls; these methods are never invoked.
namespace Agentmux.SelectedHost {
 internal static class SystemAnchorPositiveControl { internal static void Close(SystemAnchorAdmission anchor) { anchor.Close(); } }
#if NEGATIVE_CONTROL
 internal static class SystemAnchorNegativeControl { internal static void Misuse(SystemAnchorAdmission anchor) { anchor.Close(new NativeBudget(5000));new SystemAnchorAdmission(new NativeBudget(5000)); } }
#endif
}
