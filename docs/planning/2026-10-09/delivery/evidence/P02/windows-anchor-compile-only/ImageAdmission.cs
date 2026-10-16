// This fixed source is embedded in the installed release, not supplied by a
// request. Only the enrolled Microsoft system launcher may compile/load it.
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Agentmux.SelectedHost {
 public sealed class AdmittedImage : IDisposable {
  private readonly List<SafeFileHandle> ancestors;
  private readonly FileStream image;
  private readonly SafeFileHandle imageHandle;
  private Exception closeFailure;
  private readonly string path;
  private bool closed;
  private bool transferred;
  private readonly object ownership=new object();
  private AdmittedImage(List<SafeFileHandle> a, FileStream f, SafeFileHandle h, string p) { ancestors=a; image=f;imageHandle=h; path=p; }
  internal ImageLease TakeForChild(NativeBudget budget) {
   budget.Check();if(!System.Threading.Monitor.TryEnter(ownership,budget.Remaining)) throw new InvalidOperationException("host_port_deadline");
   try { budget.Check();if(closed || transferred) throw new InvalidOperationException("host_port_image_unavailable");transferred=true;return new ImageLease(this,path); }
   finally { System.Threading.Monitor.Exit(ownership); }
  }
  internal sealed class ImageLease {
   private AdmittedImage owner;internal readonly string Path;
   internal ImageLease(AdmittedImage image,string path) { owner=image;Path=path; }
   internal void ReleaseAfterJoin() { if(owner==null)return;AdmittedImage actual=owner;actual.CloseTransferred();owner=null; }
  }
  private void CloseTransferred() { lock(ownership) { if(closed) { if(closeFailure!=null)throw closeFailure;return; }closed=true; }CloseFiles(); }
  private void CloseFiles() {
   List<Exception> failures=new List<Exception>();
   try { image.Dispose(); } catch(Exception error) { failures.Add(error); }
   for(int i=ancestors.Count-1;i>=0;i--)try { Native.CloseOwned(ancestors[i]); }catch(Exception error) { failures.Add(error); }
   try { Native.CloseOwned(imageHandle); }catch(Exception error) { failures.Add(error); }
   if(failures.Count!=0) { closeFailure=new InvalidOperationException("host_port_cleanup_failed",new AggregateException(failures));throw closeFailure; }
  }

  // No user command or caller executable path is accepted. The artifact path
  // is derived only from the independently enrolled fixed release directory.
  public static AdmittedImage Open(string installedDirectory, string releaseDigest, string imageDigest, long imageBytes, string nativeOwnerSid) {
   if(!Hex(releaseDigest) || !Hex(imageDigest) || imageBytes<1 || imageBytes>33554432) throw new InvalidOperationException("host_port_image_rejected");
   if(String.IsNullOrEmpty(nativeOwnerSid)) throw new InvalidOperationException("host_port_owner_rejected");
   SecurityIdentifier owner = new SecurityIdentifier(nativeOwnerSid);
   WindowsIdentity currentIdentity=WindowsIdentity.GetCurrent();
   if(currentIdentity==null || currentIdentity.User==null || owner.Value != currentIdentity.User.Value) throw new InvalidOperationException("host_port_owner_rejected");
   string root = Path.GetFullPath(installedDirectory);
   if(!Path.IsPathRooted(root) || root.StartsWith(@"\\",StringComparison.Ordinal) || root.Length<4 || root.Substring(2).Contains(":")) throw new InvalidOperationException("host_port_path_rejected");
   string target = Path.Combine(root,"Agentmux","Observers",releaseDigest,imageDigest,"agentmux-host-observer.exe");
   List<SafeFileHandle> dirs = new List<SafeFileHandle>(); FileStream stream = null;SafeFileHandle imageOwner=null;
   try {
    string current=Path.GetPathRoot(target);
    dirs.Add(OpenDirectory(current,owner,false));
    string relative=target.Substring(current.Length);
    string[] segments=relative.Split('\\');
    for(int i=0;i<segments.Length-1;i++) {
     if(segments[i].Length==0 || segments[i]=="." || segments[i]=="..") throw new InvalidOperationException("host_port_path_rejected");
     current=Path.Combine(current,segments[i]); dirs.Add(OpenDirectory(current,owner,i==segments.Length-2));
    }
    SafeFileHandle handle=Native.CreateFile(target,0x80000000|0x00020000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
    if(handle.IsInvalid) { handle.Dispose(); throw new InvalidOperationException("host_port_image_rejected"); }
    try { Check(handle,false,owner,target,true); imageOwner=handle;stream=new FileStream(new SafeFileHandle(handle.DangerousGetHandle(),false),FileAccess.Read); }
    catch(Exception primary) { try { Native.CloseOwned(handle); }catch(Exception cleanup) { throw new InvalidOperationException("host_port_cleanup_failed",new AggregateException(primary,cleanup)); }throw; }
    if(stream.Length!=imageBytes) throw new InvalidOperationException("host_port_image_rejected");
    byte[] hash; using(SHA256 sha=SHA256.Create()) { hash=sha.ComputeHash(stream); }
    string actual=BitConverter.ToString(hash).Replace("-","").ToLowerInvariant();
    if(actual!=imageDigest || stream.Length!=imageBytes) throw new InvalidOperationException("host_port_image_rejected");
    Check(stream.SafeFileHandle,false,owner,target,true);
    stream.Position=0;
    return new AdmittedImage(dirs,stream,imageOwner,target);
   } catch(Exception primary) {
    List<Exception> failures=new List<Exception>();failures.Add(primary);
    if(stream!=null)try { stream.Dispose(); }catch(Exception cause){failures.Add(cause);}
    if(imageOwner!=null)try { Native.CloseOwned(imageOwner); }catch(Exception cause){failures.Add(cause);}
    for(int i=dirs.Count-1;i>=0;i--)try { Native.CloseOwned(dirs[i]); }catch(Exception cause){failures.Add(cause);}
    if(failures.Count>1)throw new InvalidOperationException("host_port_cleanup_failed",new AggregateException(failures));
    throw;
   }
  }
  private static bool Hex(string s) { if(s==null || s.Length!=64) return false; foreach(char c in s) if(!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return false; return true; }
  private static SafeFileHandle OpenDirectory(string path,SecurityIdentifier owner,bool imageParent) {
   // FILE_SHARE_WRITE and FILE_SHARE_DELETE are intentionally absent. This
   // prevents new write-data opens used for in-place reparse mutation.
   // Attribute/EA mutation is independently forbidden by the admitted DACL.
   // Every admitted ancestor stays
   // held across image hashing, CreateProcess and the child's actual lifetime.
   SafeFileHandle h=Native.CreateFile(path,0x00020000|0x80,1,IntPtr.Zero,3,0x02000000|0x00200000,IntPtr.Zero);
   if(h.IsInvalid) { h.Dispose(); throw new InvalidOperationException("host_port_path_rejected"); }
   try { Check(h,true,owner,path,imageParent); return h; } catch(Exception primary) { try { Native.CloseOwned(h); }catch(Exception cleanup) { throw new InvalidOperationException("host_port_cleanup_failed",new AggregateException(primary,cleanup)); }throw; }
  }
  private static void Check(SafeFileHandle h,bool directory,SecurityIdentifier expectedOwner,string expectedPath,bool imageParent) {
   Native.FileInfo info;
   if(!Native.GetFileInformationByHandle(h,out info) || (info.Attributes&0x400)!=0 || ((info.Attributes&0x10)!=0)!=directory || (!directory && info.Links!=1)) throw new InvalidOperationException("host_port_path_rejected");
   char[] chars=new char[32768]; uint length=Native.GetFinalPathNameByHandle(h,chars,(uint)chars.Length,0);
   if(length==0 || length>=chars.Length) throw new InvalidOperationException("host_port_path_rejected");
   string final=new string(chars,0,(int)length);
   if(!String.Equals(final,@"\\?\"+expectedPath,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("host_port_path_rejected");
   IntPtr o,g,d,s,descriptor;
   if(Native.GetSecurityInfo(h,1,1|4,out o,out g,out d,out s,out descriptor)!=0 || descriptor==IntPtr.Zero) throw new InvalidOperationException("host_port_acl_rejected");
   try {
    uint n=Native.GetSecurityDescriptorLength(descriptor); if(n<20 || n>65536) throw new InvalidOperationException("host_port_acl_rejected");
    byte[] raw=new byte[n]; Marshal.Copy(descriptor,raw,0,(int)n); RawSecurityDescriptor sd=new RawSecurityDescriptor(raw,0);
    if(sd.Owner==null || !Trusted(sd.Owner,expectedOwner) || sd.DiscretionaryAcl==null) throw new InvalidOperationException("host_port_acl_rejected");
    // Refuse untrusted mutation grants rather than treating deny ACEs as a
    // reason to relax the allow-list. Inherit-only ACEs do not apply here.
    foreach(GenericAce ace in sd.DiscretionaryAcl) {
     if((ace.AceFlags&AceFlags.InheritOnly)!=0) continue;
     CommonAce common=ace as CommonAce;
     if(common==null || common.IsCallback) throw new InvalidOperationException("host_port_acl_rejected");
     if(common.AceQualifier!=AceQualifier.AccessAllowed) continue;
     // Ancestor sibling creation does not rewrite an existing held child.
     // The image parent additionally forbids foreign file/subdirectory
     // creation so no application-local dependency can be planted there.
     uint mutate=0x40000000|0x10000000|0x00040000|0x00080000|0x00010000|0x00000100|0x00000010|0x00000040;
     if(!directory || imageParent) mutate|=0x00000002|0x00000004;
     if((((uint)common.AccessMask)&mutate)!=0 && !Trusted(common.SecurityIdentifier,expectedOwner)) throw new InvalidOperationException("host_port_acl_rejected");
    }
   } finally { Native.LocalFree(descriptor); }
  }
  private static bool Trusted(SecurityIdentifier sid,SecurityIdentifier owner) {
   return sid.Equals(owner) || sid.Value=="S-1-5-18" || sid.Value=="S-1-5-32-544" || sid.Value=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
  }
  public void Dispose() { lock(ownership) { if(closed)return;if(transferred)throw new InvalidOperationException("host_port_image_owned_by_child");closed=true; }CloseFiles(); }
 }
 internal static class Native {
  // This closes only a concrete handle minted by this native gate. Marking it
  // invalid consumes managed ownership even on failure; no raw-handle retry.
  internal static void CloseOwned(SafeFileHandle handle) {
   if(handle==null || handle.IsClosed || handle.IsInvalid)return;bool held=false;
   try { handle.DangerousAddRef(ref held);IntPtr exact=handle.DangerousGetHandle();handle.SetHandleAsInvalid();
    if(!CloseHandle(exact))throw new InvalidOperationException("host_port_handle_close_failed");
   }finally { if(held)handle.DangerousRelease();handle.Dispose(); }
  }
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
  [StructLayout(LayoutKind.Sequential)] internal struct FileInfo { internal uint Attributes; internal System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write; internal uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW")] internal static extern SafeFileHandle CreateFile(string name,uint access,uint sharing,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetFileInformationByHandle(SafeFileHandle h,out FileInfo info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="GetFinalPathNameByHandleW")] internal static extern uint GetFinalPathNameByHandle(SafeFileHandle h,[Out] char[] name,uint size,uint flags);
  [DllImport("advapi32.dll")] internal static extern uint GetSecurityInfo(SafeFileHandle h,uint kind,uint fields,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] internal static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr p);
 }
}
