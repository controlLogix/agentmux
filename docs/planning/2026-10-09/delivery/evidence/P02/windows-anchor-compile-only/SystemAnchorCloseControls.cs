// Authored managed-only controls. Neither method is executed by this slice.
// Reflection creates a component owner with no Windows handles. These controls
// check typed retention, not physical native ownership or cleanup success.
using System;
using System.Reflection;
using System.Threading;
namespace Agentmux.SelectedHost {
 internal static class SystemAnchorCloseControl {
  internal static bool ExpireWithinGate;
  internal static SystemAnchorAdmission ComponentOwner(NativeBudget budget) {
   ConstructorInfo constructor=typeof(SystemAnchorAdmission).GetConstructor(BindingFlags.Instance|BindingFlags.NonPublic,null,new[]{typeof(NativeBudget)},null);
   if(constructor==null)throw new Exception("unexpected_component_shape");
   return (SystemAnchorAdmission)constructor.Invoke(new object[]{budget});
  }
  internal static void Expire(NativeBudget budget) {
   FieldInfo deadline=typeof(NativeBudget).GetField("deadline",BindingFlags.Instance|BindingFlags.NonPublic);
   if(deadline==null||deadline.FieldType!=typeof(long))throw new Exception("unexpected_budget_shape");deadline.SetValue(budget,0L);
  }
  // This hook appears only in the separate copied control source.
  internal static void AfterGate(SystemAnchorAdmission anchor) {
   if(!ExpireWithinGate)return;
   FieldInfo field=typeof(SystemAnchorAdmission).GetField("originalBudget",BindingFlags.Instance|BindingFlags.NonPublic);
   if(field==null)throw new Exception("unexpected_owner_shape");Expire((NativeBudget)field.GetValue(anchor));
  }
  private static void RequireOwner(SystemAnchorAdmission actual) {
   try { actual.Close();throw new Exception("deadline_owner_lost"); }
   catch(SystemAnchorCleanupFailure error) {
    if(!Object.ReferenceEquals(error.Owner,actual)||error.InnerException==null||error.ToString()!="host_port_os_anchor_cleanup_failed")throw new Exception("typed_owner_not_retained");
   }
  }
  internal static void ExpiredBeforeCloseRetainsOwner() {
   NativeBudget budget=new NativeBudget(5000);SystemAnchorAdmission owner=ComponentOwner(budget);Expire(budget);ExpireWithinGate=false;RequireOwner(owner);
  }
  internal static void ExpiredAfterGateRetainsOwner() {
   NativeBudget budget=new NativeBudget(5000);SystemAnchorAdmission owner=ComponentOwner(budget);ExpireWithinGate=true;
   try { RequireOwner(owner); }
   finally { ExpireWithinGate=false; }
   FieldInfo field=typeof(SystemAnchorAdmission).GetField("ownership",BindingFlags.Instance|BindingFlags.NonPublic);object gate=field.GetValue(owner);
   bool entered=false;try { entered=Monitor.TryEnter(gate,0);if(!entered)throw new Exception("cleanup_gate_not_released"); }finally{if(entered)Monitor.Exit(gate);}
  }
 }
}
