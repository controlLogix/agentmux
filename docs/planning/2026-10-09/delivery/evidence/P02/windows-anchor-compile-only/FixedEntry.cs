// This controller is part of the fixed, separately admitted prebuilt DLL.
// The fixed Microsoft launcher must retain the controller when cleanup fails.
// No request chooses a command, executable pathname, callback or process ID.
using System;
using System.Threading;

namespace Agentmux.SelectedHost {
 internal sealed class FixedEntryOperation {
  private readonly SemaphoreSlim gate = new SemaphoreSlim(1, 1);
  private readonly NativeBudget originalBudget;
  private AdmittedImage image;
  private OwnedChild child;
  private Exception primaryFailure;
  private Exception cleanupFailure;
  private Exception imageCloseFailure;
  private bool started;
  private bool consumed;
  private bool cleanupComplete;

  private FixedEntryOperation(AdmittedImage admittedImage, NativeBudget initialBudget) {
   image = admittedImage;
   originalBudget = initialBudget;
  }

  // Only the release loader inside this same fixed DLL calls this method.
  // It must have independently admitted the Windows OS anchor, physical host,
  // selected engine namespace and signed observer declaration. AdmittedImage
  // alone proves the held file checks, not those enrollment decisions.
  internal static FixedEntryOperation Begin(AdmittedImage admittedImage,
      byte[] fixedRequest, string enrolledSystemRoot, NativeBudget originalBudget) {
   if (admittedImage == null || originalBudget == null)
    throw new FixedEntryFailure("host_port_admission_rejected", null);
   FixedEntryOperation actual = new FixedEntryOperation(admittedImage, originalBudget);
   try {
    actual.originalBudget.Check();
    actual.child = OwnedChild.Start(admittedImage, fixedRequest,
                                   enrolledSystemRoot, actual.originalBudget);
    actual.started = true;
    return actual;
   } catch (Exception failure) {
    actual.primaryFailure = failure;
    NativeCleanupException retained = failure as NativeCleanupException;
    if (retained != null) actual.child = retained.Owner;
    // OwnedChild.Start either joined its child or returns its concrete owner.
    // The controller also retains an image whose transfer never completed.
    actual.CleanupAfterFailure();
    throw new FixedEntryFailure("host_port_observation_unavailable", failure);
   }
  }

  // One result may be consumed. No result escapes before the same operation
  // has joined its child and pipe workers and closed its admitted image owners.
  internal byte[] ReadResultAndJoin() {
   Enter();
   try {
    if (!started || consumed || child == null)
     throw new FixedEntryFailure("host_port_request_invalid", null);
    consumed = true;
    byte[] result = null;
    try {
     originalBudget.Check();
     result = child.ReadAndJoin(originalBudget);
     if (result == null || result.Length == 0 || result.Length > 1024)
      throw new FixedEntryFailure("host_port_frame_invalid", null);
    } catch (Exception failure) {
     primaryFailure = failure;
     NativeCleanupException retained = failure as NativeCleanupException;
     if (retained != null) child = retained.Owner;
    }
    CleanupLocked();
    if (primaryFailure != null)
     throw new FixedEntryFailure("host_port_observation_unavailable", primaryFailure);
    byte[] copy = new byte[result.Length];
    Array.Copy(result, copy, result.Length);
    return copy;
   } finally {
    gate.Release();
   }
  }

  // Cleanup retries never start another observer or publish a delayed result.
  // Every call retains the exact initial operation budget. An expired budget
  // preserves ownership; a retry cannot replace or reset that budget.
  internal void CancelAndJoin() {
   Enter();
   try {
    CleanupLocked();
   } finally {
    gate.Release();
   }
  }

  private void Enter() {
   bool entered;
   try { entered = gate.Wait(originalBudget.Remaining); }
   catch (Exception failure) { throw Retained(failure); }
   if (!entered) throw Retained(new FixedEntryFailure("host_port_deadline", null));
  }

  private void CleanupAfterFailure() {
   Enter();
   try {
    CleanupLocked();
   } finally {
    gate.Release();
   }
  }

  private void CleanupLocked() {
   if (cleanupComplete) {
    if (cleanupFailure != null) throw Retained(cleanupFailure);
    return;
   }
   try {
    // Expired budgets retain ownership. They do not authorize another spawn,
    // an unbounded join or a new cleanup allowance.
    originalBudget.Check();
    // A failed image Dispose consumed its close attempts. Preserve uncertainty
    // rather than treating a later no-op Dispose as a successful close.
    if (imageCloseFailure != null) throw imageCloseFailure;
    if (child != null) {
     child.Close(originalBudget);
     child = null;
     // Successful child cleanup already released its transferred image lease.
    }
    if (image != null) {
     try { image.Dispose(); }
     catch (Exception failure) { imageCloseFailure = failure;throw; }
     image = null;
    }
    // The earlier immutable error still retains its own cause. A transient
    // deadline failure must not make a later joined cleanup fail spuriously.
    cleanupFailure = null;
    cleanupComplete = true;
   } catch (Exception failure) {
    cleanupFailure = failure;
    NativeCleanupException retained = failure as NativeCleanupException;
    if (retained != null) child = retained.Owner;
    throw Retained(failure);
   }
  }

  private FixedEntryCleanupFailure Retained(Exception failure) {
   return new FixedEntryCleanupFailure(this, primaryFailure, failure);
  }
 }

 // No public cause or native handle is serialized. The fixed loader keeps this
 // exception and controller inside its own process until cleanup joins. It must
 // not print Exception.Data, a stack trace or any private cause to either pipe.
 internal sealed class FixedEntryCleanupFailure : Exception {
  internal readonly FixedEntryOperation Owner;
  internal readonly Exception PrimaryCause;
  internal readonly Exception CleanupCause;
  internal FixedEntryCleanupFailure(FixedEntryOperation actual,
      Exception primary, Exception cleanup) : base("host_port_cleanup_incomplete") {
   Owner = actual;
   PrimaryCause = primary;
   CleanupCause = cleanup;
  }
  public override string ToString() { return "host_port_cleanup_incomplete"; }
 }

 internal sealed class FixedEntryFailure : Exception {
  internal readonly Exception Cause;
  internal FixedEntryFailure(string fixedCode, Exception cause) : base(fixedCode) {
   Cause = cause;
  }
  public override string ToString() { return Message; }
 }
}
