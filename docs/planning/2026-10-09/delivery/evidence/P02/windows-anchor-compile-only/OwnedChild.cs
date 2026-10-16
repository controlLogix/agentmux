// Fixed native child launch mechanics. This source accepts no command, shell,
// callback or PID. AdmittedImage supplies the sole executable pathname.
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Agentmux.SelectedHost {
 internal sealed class OwnedChild {
  private SafeFileHandle job, process, input, output, error;
  private bool joined;
  private readonly System.Threading.SemaphoreSlim cleanupGate=new System.Threading.SemaphoreSlim(1,1);
  private readonly System.Collections.Generic.List<Exception> closeFailures=new System.Collections.Generic.List<Exception>();
  private AdmittedImage.ImageLease imageLease;
  private Task<byte[]> inputTask,outputTask,errorTask;
  private OwnedChild() {}
  internal static OwnedChild Start(AdmittedImage image, byte[] request, string enrolledSystemRoot, NativeBudget budget) {
   if(image==null || request==null || request.Length<1 || request.Length>1024 || budget==null) throw new InvalidOperationException("host_port_launch_rejected");
   budget.Check();
   OwnedChild child=new OwnedChild();child.imageLease=image.TakeForChild(budget); SafeFileHandle inRead=null,outWrite=null,errWrite=null,thread=null;
   IntPtr attributes=IntPtr.Zero, handleList=IntPtr.Zero, jobList=IntPtr.Zero, environment=IntPtr.Zero;bool initialized=false;Exception startFailure=null;
   try {
    budget.Check();
    char[] windowsPath=new char[32768];uint windowsLength=ChildNative.GetWindowsDirectory(windowsPath,(uint)windowsPath.Length);
    if(windowsLength==0 || windowsLength>=windowsPath.Length || !String.Equals(new string(windowsPath,0,(int)windowsLength),enrolledSystemRoot,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("host_port_os_anchor_rejected");
    string system32=Path.Combine(enrolledSystemRoot,"System32");
    child.job=ChildNative.CreateJobObject(IntPtr.Zero,null);
    if(child.job.IsInvalid) throw new InvalidOperationException("host_port_launch_failed");
    ChildNative.ExtendedLimits limits=new ChildNative.ExtendedLimits(); limits.Basic.Flags=0x2000; // KILL_ON_JOB_CLOSE.
    if(!ChildNative.SetInformationJobObject(child.job,9,ref limits,(uint)Marshal.SizeOf(limits))) throw new InvalidOperationException("host_port_launch_failed");
    ChildNative.Security security=new ChildNative.Security(); security.Length=Marshal.SizeOf(security);security.Inherit=1;
    if(!ChildNative.CreatePipe(out inRead,out child.input,ref security,4096) || !ChildNative.CreatePipe(out child.output,out outWrite,ref security,4096) || !ChildNative.CreatePipe(out child.error,out errWrite,ref security,4096)) throw new InvalidOperationException("host_port_pipe_failed");
    if(!ChildNative.SetHandleInformation(child.input,1,0) || !ChildNative.SetHandleInformation(child.output,1,0) || !ChildNative.SetHandleInformation(child.error,1,0)) throw new InvalidOperationException("host_port_pipe_failed");
    UIntPtr bytes=UIntPtr.Zero; ChildNative.InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref bytes);
    if(bytes.ToUInt64()==0 || bytes.ToUInt64()>65536) throw new InvalidOperationException("host_port_launch_failed");
    attributes=Marshal.AllocHGlobal((int)bytes.ToUInt64());
    if(!ChildNative.InitializeProcThreadAttributeList(attributes,2,0,ref bytes)) throw new InvalidOperationException("host_port_launch_failed");
    initialized=true;
    handleList=Marshal.AllocHGlobal(IntPtr.Size*3);
    Marshal.WriteIntPtr(handleList,0,inRead.DangerousGetHandle()); Marshal.WriteIntPtr(handleList,IntPtr.Size,outWrite.DangerousGetHandle()); Marshal.WriteIntPtr(handleList,IntPtr.Size*2,errWrite.DangerousGetHandle());
    if(!ChildNative.UpdateProcThreadAttribute(attributes,0,(IntPtr)0x20002,handleList,(UIntPtr)(IntPtr.Size*3),IntPtr.Zero,IntPtr.Zero)) throw new InvalidOperationException("host_port_launch_failed");
    // Windows 10+ assigns the exact owned job during creation, avoiding
    // a parent-death gap between CreateProcess and later job assignment.
    jobList=Marshal.AllocHGlobal(IntPtr.Size);Marshal.WriteIntPtr(jobList,child.job.DangerousGetHandle());
    if(!ChildNative.UpdateProcThreadAttribute(attributes,0,(IntPtr)0x2000d,jobList,(UIntPtr)IntPtr.Size,IntPtr.Zero,IntPtr.Zero)) throw new InvalidOperationException("host_port_job_failed");
    ChildNative.Startup startup=new ChildNative.Startup(); startup.Info.Size=Marshal.SizeOf(startup);startup.Info.Flags=0x100;startup.Info.Input=inRead.DangerousGetHandle();startup.Info.Output=outWrite.DangerousGetHandle();startup.Info.Error=errWrite.DangerousGetHandle();startup.Attributes=attributes;
    // The fixed OS anchor is separately enrolled. No inherited PATH, loader,
    // profile, current directory or environment is accepted by this child.
    environment=Marshal.StringToHGlobalUni("PATH="+system32+"\0SystemRoot="+enrolledSystemRoot+"\0\0");
    budget.Check();
    string path=child.imageLease.Path; ChildNative.ProcessInfo info;
    if(!ChildNative.CreateProcess(path,new StringBuilder("\""+path+"\" --observe-loopback-tcp"),IntPtr.Zero,IntPtr.Zero,true,0x4|0x80000|0x08000000|0x400,environment,system32,ref startup,out info)) throw new InvalidOperationException("host_port_launch_failed");
    child.process=new SafeFileHandle(info.Process,true);thread=new SafeFileHandle(info.Thread,true);
    // Only the fresh child, already in the owned job, can be resumed.
    if(ChildNative.ResumeThread(thread)==0xffffffff) throw new InvalidOperationException("host_port_launch_failed");
    budget.Check();
    child.outputTask=Task.Factory.StartNew(()=>ReadBounded(child.output));
    child.errorTask=Task.Factory.StartNew(()=>ReadBounded(child.error));
    child.inputTask=Task.Factory.StartNew(()=>WriteRequest(child.input,request));
    if(!child.inputTask.Wait(budget.Remaining)) throw new InvalidOperationException("host_port_deadline");
    if(child.inputTask.IsFaulted) throw new InvalidOperationException("host_port_pipe_failed",child.inputTask.Exception);
    Native.CloseOwned(child.input);child.input=null; // Actual joined writer now sends EOF.
    budget.Check();
    return child;
   } catch(Exception cause) {
    startFailure=cause;
    try { child.Close(budget); } catch(Exception cleanup) { throw new NativeCleanupException(child,new AggregateException(cause,cleanup)); }
    throw;
   }
   finally {
    // Every temporary native owner is consumed once, even if another close
    // fails. A late failure cannot discard either the child or start cause.
    System.Collections.Generic.List<Exception> finalFailures=new System.Collections.Generic.List<Exception>();
    foreach(SafeFileHandle temporary in new SafeFileHandle[]{thread,inRead,outWrite,errWrite})
     if(temporary!=null)try { Native.CloseOwned(temporary); }catch(Exception cause){finalFailures.Add(cause);}
    if(attributes!=IntPtr.Zero) { if(initialized)ChildNative.DeleteProcThreadAttributeList(attributes);Marshal.FreeHGlobal(attributes); }
    if(handleList!=IntPtr.Zero) Marshal.FreeHGlobal(handleList);if(jobList!=IntPtr.Zero) Marshal.FreeHGlobal(jobList);if(environment!=IntPtr.Zero) Marshal.FreeHGlobal(environment);
    if(finalFailures.Count!=0) {
     if(startFailure!=null)finalFailures.Add(startFailure);
     child.closeFailures.AddRange(finalFailures);
     try { child.Close(budget); }catch(Exception cause){finalFailures.Add(cause);}
     throw new NativeCleanupException(child,new AggregateException(finalFailures));
    }

   }
  }
  internal byte[] ReadAndJoin(NativeBudget budget) {
   if(budget==null || process==null || joined) throw new InvalidOperationException("host_port_request_invalid");
   uint wait=ChildNative.WaitForSingleObject(process,(uint)budget.Remaining);
   if(wait!=0) {
    Exception cause=new InvalidOperationException(wait==258 ? "host_port_deadline" : "host_port_wait_failed");
    try { Close(budget); } catch(Exception cleanup) { throw new NativeCleanupException(this,new AggregateException(cause,cleanup)); }
    throw cause;
   }
   joined=true;
   if(!TasksJoined(budget)) throw new NativeCleanupException(this,new InvalidOperationException("host_port_deadline"));
   uint code;if(!ChildNative.GetExitCodeProcess(process,out code) || code!=0 || errorTask.Result.Length!=0) throw new InvalidOperationException("host_port_observation_unavailable");
   return outputTask.Result;
  }
  private bool TasksJoined(NativeBudget budget) {
   Task[] tasks=ActiveTasks();if(tasks.Length==0)return true;
   try { return Task.WaitAll(tasks,budget.Remaining); }
   catch(AggregateException) { foreach(Task task in tasks)if(!task.IsCompleted)return false;return true; }
  }
  private Task[] ActiveTasks() {
   System.Collections.Generic.List<Task> tasks=new System.Collections.Generic.List<Task>();
   if(inputTask!=null)tasks.Add(inputTask);if(outputTask!=null)tasks.Add(outputTask);if(errorTask!=null)tasks.Add(errorTask);return tasks.ToArray();
  }
  private static byte[] WriteRequest(SafeFileHandle handle,byte[] request) {
   // Borrowed wrappers never consume the central owned pipe handle. The child
   // closes that handle only after this actual writer has joined.
   using(SafeFileHandle borrowed=new SafeFileHandle(handle.DangerousGetHandle(),false))
   using(FileStream stream=new FileStream(borrowed,FileAccess.Write)) { stream.Write(request,0,request.Length);stream.Flush(); }
   return new byte[0];
  }
  private static byte[] ReadBounded(SafeFileHandle h) {
   using(SafeFileHandle borrowed=new SafeFileHandle(h.DangerousGetHandle(),false))
   using(FileStream stream=new FileStream(borrowed,FileAccess.Read)) {
    byte[] data=new byte[1025];int n=0;
    while(n<data.Length) { int got=stream.Read(data,n,data.Length-n);if(got==0) break;n+=got; }
    if(n>1024) throw new InvalidOperationException("host_port_frame_invalid");
    byte[] result=new byte[n];Array.Copy(data,result,n);return result;
   }
  }
  private NativeCleanupException FailureWithRetainedCauses(Exception cause) {
   System.Collections.Generic.List<Exception> all=new System.Collections.Generic.List<Exception>(closeFailures);all.Add(cause);return new NativeCleanupException(this,new AggregateException(all));
  }
  // Retry retains only this factory-created child, job, pipes, workers and
  // image lease. It accepts an existing bounded cleanup budget, not a PID.
  internal void Close(NativeBudget budget) {
   if(budget==null || !cleanupGate.Wait(budget.Remaining))throw new NativeCleanupException(this,new InvalidOperationException("host_port_cleanup_incomplete"));
   try {
    if(job!=null) {
     SafeFileHandle exact=job;job=null;
     try { Native.CloseOwned(exact); }catch(Exception cause) {
      closeFailures.Add(cause);
      // A failed consumed job close cannot be retried by its numeric handle.
      // Cancellation may use only this factory-created process still owned.
      if(process!=null && !joined && !ChildNative.TerminateProcess(process,2))closeFailures.Add(new InvalidOperationException("host_port_cancel_failed"));
     }
    }
    if(process!=null && !joined) {
     uint wait=ChildNative.WaitForSingleObject(process,(uint)budget.Remaining);
     if(wait!=0)throw FailureWithRetainedCauses(new InvalidOperationException("host_port_cleanup_incomplete"));
     joined=true;
    }
    if(!TasksJoined(budget))throw FailureWithRetainedCauses(new InvalidOperationException("host_port_cleanup_incomplete"));
    // Close every concrete pipe/process owner, preserving every failure. No
    // consumed Windows handle is reconstructed or retried.
    SafeFileHandle[] handles={input,output,error,process};input=null;output=null;error=null;process=null;
    foreach(SafeFileHandle handle in handles)if(handle!=null)try { Native.CloseOwned(handle); }catch(Exception cause){closeFailures.Add(cause);}
    if(imageLease!=null)try { imageLease.ReleaseAfterJoin();imageLease=null; }catch(Exception cause){closeFailures.Add(cause);}
    if(closeFailures.Count!=0)throw new NativeCleanupException(this,new AggregateException(closeFailures));
   } finally { cleanupGate.Release(); }
  }

 }
 internal sealed class NativeCleanupException : Exception {
  internal readonly OwnedChild Owner;
  internal NativeCleanupException(OwnedChild owner,Exception cause):base("host_port_cleanup_incomplete",cause) { Owner=owner; }
  public override string ToString() { return "host_port_cleanup_incomplete"; }
 }
 internal static class ChildNative {
  [StructLayout(LayoutKind.Sequential)] internal struct Security { internal int Length;internal IntPtr Descriptor;internal int Inherit; }
  [StructLayout(LayoutKind.Sequential)] internal struct BasicLimits { internal long ProcessTime,JobTime;internal uint Flags;internal UIntPtr Minimum,Maximum;internal uint ActiveProcesses;internal UIntPtr Affinity;internal uint Priority,Scheduling; }
  [StructLayout(LayoutKind.Sequential)] internal struct Counters { internal ulong ReadOperations,WriteOperations,OtherOperations,ReadBytes,WriteBytes,OtherBytes; }
  [StructLayout(LayoutKind.Sequential)] internal struct ExtendedLimits { internal BasicLimits Basic;internal Counters IO;internal UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] internal struct StartupInfo { internal int Size;internal string Reserved,Desktop,Title;internal uint X,Y,Width,Height,XChars,YChars,Fill,Flags;internal ushort Show,ReservedSize;internal IntPtr ReservedBytes,Input,Output,Error; }
  [StructLayout(LayoutKind.Sequential)] internal struct Startup { internal StartupInfo Info;internal IntPtr Attributes; }
  [StructLayout(LayoutKind.Sequential)] internal struct ProcessInfo { internal IntPtr Process,Thread;internal uint ProcessID,ThreadID; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,EntryPoint="GetWindowsDirectoryW")] internal static extern uint GetWindowsDirectory([Out]char[] name,uint length);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] internal static extern SafeFileHandle CreateJobObject(IntPtr security,string name);
  [DllImport("kernel32.dll")] internal static extern bool SetInformationJobObject(SafeFileHandle job,uint kind,ref ExtendedLimits limits,uint size);
  [DllImport("kernel32.dll")] internal static extern bool CreatePipe(out SafeFileHandle read,out SafeFileHandle write,ref Security security,uint size);
  [DllImport("kernel32.dll")] internal static extern bool SetHandleInformation(SafeFileHandle handle,uint mask,uint flags);
  [DllImport("kernel32.dll")] internal static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref UIntPtr size);
  [DllImport("kernel32.dll")] internal static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,UIntPtr size,IntPtr previous,IntPtr returned);
  [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,EntryPoint="CreateProcessW")] internal static extern bool CreateProcess(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out ProcessInfo info);
  [DllImport("kernel32.dll")] internal static extern bool AssignProcessToJobObject(SafeFileHandle job,SafeFileHandle process);
  [DllImport("kernel32.dll")] internal static extern uint ResumeThread(SafeFileHandle thread);
  [DllImport("kernel32.dll")] internal static extern bool TerminateProcess(SafeFileHandle process,uint code);
  [DllImport("kernel32.dll")] internal static extern uint WaitForSingleObject(SafeFileHandle handle,uint milliseconds);
  [DllImport("kernel32.dll")] internal static extern bool GetExitCodeProcess(SafeFileHandle process,out uint code);
 }
}
