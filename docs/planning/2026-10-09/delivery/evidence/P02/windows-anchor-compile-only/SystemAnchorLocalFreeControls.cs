// Pure modeled allocation controls, authored but unexecuted. A synthetic value
// is installed only in a component owner and intercepted by the copied source.
// It is never passed to Windows LocalFree or adopted by production.
using System;
using System.Reflection;
namespace Agentmux.SelectedHost {
 internal static class SystemAnchorLocalFreeControl {
  internal static int Calls,Mode;
  internal static IntPtr Free(IntPtr original){Calls++;if(Mode==2)throw new Exception("private modeled uncertainty");return Mode==0?IntPtr.Zero:original;}
  private static FieldInfo Field(string name){FieldInfo field=typeof(SystemAnchorAdmission).GetField(name,BindingFlags.Instance|BindingFlags.NonPublic);if(field==null)throw new Exception("unexpected_owner_shape");return field;}
  private static SystemAnchorAdmission Owner(){SystemAnchorAdmission owner=SystemAnchorCloseControl.ComponentOwner(new NativeBudget(5000));Field("securityDescriptor").SetValue(owner,new IntPtr(0x1234));Calls=0;SystemAnchorCloseControl.ExpireWithinGate=false;return owner;}
  private static void RequireRetained(SystemAnchorAdmission owner){try{owner.Close();throw new Exception("allocation_owner_lost");}catch(SystemAnchorCleanupFailure error){if(!Object.ReferenceEquals(error.Owner,owner)||(IntPtr)Field("securityDescriptor").GetValue(owner)!=new IntPtr(0x1234))throw new Exception("original_allocation_not_retained");}}
  internal static void KnownRefusalThenSuccessfulExactRetry(){SystemAnchorAdmission owner=Owner();Mode=1;RequireRetained(owner);if(Calls!=1)throw new Exception("unexpected_free_count");Mode=0;owner.Close();if(Calls!=2||(IntPtr)Field("securityDescriptor").GetValue(owner)!=IntPtr.Zero)throw new Exception("successful_exact_free_not_recorded");}
  internal static void UnknownOutcomeNeverRetries(){SystemAnchorAdmission owner=Owner();Mode=2;RequireRetained(owner);Mode=0;RequireRetained(owner);if(Calls!=1)throw new Exception("uncertain_allocation_was_retried");}
  internal static void SuccessNeverFreesAgain(){SystemAnchorAdmission owner=Owner();Mode=0;owner.Close();owner.Close();if(Calls!=1||(IntPtr)Field("securityDescriptor").GetValue(owner)!=IntPtr.Zero)throw new Exception("consumed_allocation_reused");}
 }
}
