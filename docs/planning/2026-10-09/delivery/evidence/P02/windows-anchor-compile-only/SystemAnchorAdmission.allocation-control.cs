// Source for the fixed prebuilt bootstrap only. This does not authorize its own
// initial execution or enroll a Docker-to-Windows namespace relationship.
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
namespace Agentmux.SelectedHost {
 internal sealed class SystemArtifactPin {
  internal readonly string SHA256, SignerSHA256;
  internal readonly long Bytes;
  internal SystemArtifactPin(string digest,long bytes,string signer) { SHA256=digest;Bytes=bytes;SignerSHA256=signer; }
  internal bool Valid { get { return SystemAnchorAdmission.Hex(SHA256)&&SystemAnchorAdmission.Hex(SignerSHA256)&&Bytes>0&&Bytes<=67108864; } }
 }
 // These expectations must come from independent private OS enrollment. Neither
 // a request, WSL hash, nor this bootstrap's output may create that provenance.
 internal sealed class SystemAnchorExpected {
  internal readonly string WindowsDirectory;
  internal readonly SystemArtifactPin Bootstrap,CLR,CoreLibrary;
  internal SystemAnchorExpected(string root,SystemArtifactPin bootstrap,SystemArtifactPin clr,SystemArtifactPin core) { WindowsDirectory=root;Bootstrap=bootstrap;CLR=clr;CoreLibrary=core; }
 }
 internal sealed class SystemAnchorAdmission {
  private readonly NativeBudget originalBudget;
  private readonly List<SafeFileHandle> handles=new List<SafeFileHandle>();
  private readonly object ownership=new object();
  private Exception closeFailure;
  private SafeFileHandle pendingHandle;
  private IntPtr securityDescriptor;
  private bool securityDescriptorUncertain;
  private bool closed;
  private SystemAnchorAdmission(NativeBudget budget) { originalBudget=budget; }
  internal static SystemAnchorAdmission Open(SystemAnchorExpected expected,NativeBudget budget) {
   if(expected==null||budget==null||expected.Bootstrap==null||expected.CLR==null||expected.CoreLibrary==null||!expected.Bootstrap.Valid||!expected.CLR.Valid||!expected.CoreLibrary.Valid)throw new SystemAnchorFailure(null);
   budget.Check();SystemAnchorAdmission actual=new SystemAnchorAdmission(budget);
   try {
    string root=Path.GetFullPath(expected.WindowsDirectory);
    if(root.Length<4||!Path.IsPathRooted(root)||root.StartsWith(@"\\",StringComparison.Ordinal)||root.Substring(2).Contains(":"))throw new SystemAnchorFailure(null);
    char[] name=new char[32768];uint count=SystemNative.GetWindowsDirectory(name,(uint)name.Length);
    budget.Check();if(count==0||count>=name.Length||!String.Equals(new string(name,0,(int)count).TrimEnd('\\'),root.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new SystemAnchorFailure(null);
    string bootstrap=Path.Combine(root,"System32","WindowsPowerShell","v1.0","powershell.exe");
    count=SystemNative.GetModuleFileName(IntPtr.Zero,name,(uint)name.Length);
    budget.Check();if(count==0||count>=name.Length||!String.Equals(new string(name,0,(int)count),bootstrap,StringComparison.OrdinalIgnoreCase))throw new SystemAnchorFailure(null);
    actual.HoldFixed(bootstrap,expected.Bootstrap);
    actual.HoldFixed(Path.Combine(root,"Microsoft.NET","Framework64","v4.0.30319","clr.dll"),expected.CLR);
    actual.HoldFixed(Path.Combine(root,"Microsoft.NET","Framework64","v4.0.30319","mscorlib.dll"),expected.CoreLibrary);
    budget.Check();return actual;
   } catch(Exception primary) {
    try { actual.Close(); }catch(Exception cleanup) { throw new SystemAnchorCleanupFailure(actual,primary,cleanup); }
    throw new SystemAnchorFailure(primary);
   }
  }
  private void HoldFixed(string path,SystemArtifactPin pin) {
   string current=Path.GetPathRoot(path);Hold(current,true,false);
   string[] parts=path.Substring(current.Length).Split('\\');
   for(int i=0;i<parts.Length-1;i++){if(parts[i].Length==0||parts[i]=="."||parts[i]=="..")throw new SystemAnchorFailure(null);current=Path.Combine(current,parts[i]);Hold(current,true,i==parts.Length-2);}
   SafeFileHandle image=Hold(path,false,true);Native.FileInfo before;
   if(!Native.GetFileInformationByHandle(image,out before))throw new SystemAnchorFailure(null);
   using(FileStream stream=new FileStream(new SafeFileHandle(image.DangerousGetHandle(),false),FileAccess.Read)) {
    if(stream.Length!=pin.Bytes)throw new SystemAnchorFailure(null);
    byte[] buffer=new byte[65536];long total=0;
    using(SHA256 hash=SHA256.Create()) {
     for(;;){originalBudget.Check();int n=stream.Read(buffer,0,buffer.Length);originalBudget.Check();if(n==0)break;total+=n;if(total>pin.Bytes)throw new SystemAnchorFailure(null);hash.TransformBlock(buffer,0,n,null,0);}
     hash.TransformFinalBlock(new byte[0],0,0);if(total!=pin.Bytes||ToHex(hash.Hash)!=pin.SHA256)throw new SystemAnchorFailure(null);
    }
   }
   originalBudget.Check();
   // Verify Authenticode offline on the held, nonreplaceable fixed pathname.
   if(!SystemNative.SignatureValid(path))throw new SystemAnchorFailure(null);
   using(X509Certificate certificate=X509Certificate.CreateFromSignedFile(path))using(SHA256 hash=SHA256.Create()) { if(ToHex(hash.ComputeHash(certificate.GetRawCertData()))!=pin.SignerSHA256)throw new SystemAnchorFailure(null); }
   originalBudget.Check();Native.FileInfo after;
   if(!Native.GetFileInformationByHandle(image,out after)||before.Volume!=after.Volume||before.IndexHigh!=after.IndexHigh||before.IndexLow!=after.IndexLow)throw new SystemAnchorFailure(null);
   Check(image,path,false,true);originalBudget.Check();
  }
  private SafeFileHandle Hold(string path,bool directory,bool leafParent) {
   originalBudget.Check();SafeFileHandle handle=Native.CreateFile(path,0x80000000|0x00020000,1,IntPtr.Zero,3,0x00200000|(directory?0x02000000u:0u),IntPtr.Zero);
   // Retain every minted owner before validation can throw. Close consumes a
   // handle even if Windows reports an error; numeric descriptor retry is unsafe.
   pendingHandle=handle;handles.Add(handle);pendingHandle=null;originalBudget.Check();if(handle.IsInvalid)throw new SystemAnchorFailure(null);Check(handle,path,directory,leafParent);return handle;
  }
  private static bool TrustedSystem(SecurityIdentifier sid) { return sid!=null&&(sid.Value=="S-1-5-18"||sid.Value=="S-1-5-32-544"||sid.Value=="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"); }
  private void Check(SafeFileHandle handle,string path,bool directory,bool leafParent) {
   Native.FileInfo info;if(!Native.GetFileInformationByHandle(handle,out info)||(info.Attributes&0x400)!=0||((info.Attributes&0x10)!=0)!=directory||(!directory&&info.Links!=1))throw new SystemAnchorFailure(null);
   char[] name=new char[32768];uint count=Native.GetFinalPathNameByHandle(handle,name,(uint)name.Length,0);if(count==0||count>=name.Length||!String.Equals(new string(name,0,(int)count),@"\\?\"+path,StringComparison.OrdinalIgnoreCase))throw new SystemAnchorFailure(null);
   if(securityDescriptor!=IntPtr.Zero)throw new SystemAnchorCleanupFailure(this,null,new SystemAnchorFailure(null));
   IntPtr owner,group,dacl,sacl,descriptor;if(Native.GetSecurityInfo(handle,1,1|4,out owner,out group,out dacl,out sacl,out descriptor)!=0||descriptor==IntPtr.Zero)throw new SystemAnchorFailure(null);
   // Only this successful GetSecurityInfo call mints the allocation owner.
   // A failed LocalFree retains this original allocation, never its return value.
   securityDescriptor=descriptor;Exception validationFailure=null;
   try {
    uint size=Native.GetSecurityDescriptorLength(descriptor);if(size<20||size>65536)throw new SystemAnchorFailure(null);byte[] raw=new byte[size];Marshal.Copy(descriptor,raw,0,(int)size);RawSecurityDescriptor security=new RawSecurityDescriptor(raw,0);if(!TrustedSystem(security.Owner)||security.DiscretionaryAcl==null)throw new SystemAnchorFailure(null);
    foreach(GenericAce ace in security.DiscretionaryAcl) {
     if((ace.AceFlags&AceFlags.InheritOnly)!=0)continue;CommonAce common=ace as CommonAce;if(common==null||common.IsCallback)throw new SystemAnchorFailure(null);if(common.AceQualifier!=AceQualifier.AccessAllowed)continue;
     uint mutation=0x40000000|0x10000000|0x00040000|0x00080000|0x00010000|0x00000100|0x00000010|0x00000040;if(!directory||leafParent)mutation|=2|4;if((((uint)common.AccessMask)&mutation)!=0&&!TrustedSystem(common.SecurityIdentifier))throw new SystemAnchorFailure(null);
    }
   } catch(Exception cause) { validationFailure=cause;throw; }
   finally { try { FreeSecurityDescriptor(); }catch(Exception cleanup){throw new SystemAnchorCleanupFailure(this,validationFailure,cleanup);} }
  }
  private void FreeSecurityDescriptor() {
   if(securityDescriptor==IntPtr.Zero)return;
   originalBudget.Check();
   if(securityDescriptorUncertain)throw new SystemAnchorFailure(null);
   IntPtr result;
   try { result=SystemAnchorLocalFreeControl.Free(securityDescriptor); }
   catch(Exception cause){securityDescriptorUncertain=true;throw new SystemAnchorFailure(cause);}
   if(result!=IntPtr.Zero)throw new SystemAnchorFailure(null);
   securityDescriptor=IntPtr.Zero;
  }
  internal void Close() {
   // Failure before or after gate acquisition retains this exact owner. No
   // expired operation receives a replacement budget or another native close.
   try {
    originalBudget.Check();
    if(!System.Threading.Monitor.TryEnter(ownership,originalBudget.Remaining))throw new SystemAnchorFailure(null);
   } catch(Exception cause) { throw new SystemAnchorCleanupFailure(this,null,cause); }
   try {
    SystemAnchorCloseControl.AfterGate(this);
    originalBudget.Check();Exception descriptorFailure=null;
    try { FreeSecurityDescriptor(); }catch(Exception cause){descriptorFailure=cause;}
    List<Exception> failures=new List<Exception>();closed=true;
    // CloseOwned ignores already-consumed owners. A retry touches only remaining
    // exact valid SafeFileHandle objects, never reconstructed numeric handles.
    if(pendingHandle!=null)try { originalBudget.Check();Native.CloseOwned(pendingHandle); }catch(Exception error){failures.Add(error);}
    for(int i=handles.Count-1;i>=0;i--)try { originalBudget.Check();Native.CloseOwned(handles[i]); }catch(Exception error){failures.Add(error);}
    if(failures.Count!=0)closeFailure=closeFailure==null?(Exception)new AggregateException(failures):new AggregateException(closeFailure,new AggregateException(failures));
    if(descriptorFailure!=null||closeFailure!=null)throw new SystemAnchorCleanupFailure(this,closeFailure,descriptorFailure??closeFailure);
   } catch(SystemAnchorCleanupFailure) { throw; }
   catch(Exception cause) { throw new SystemAnchorCleanupFailure(this,null,cause); }
   finally { System.Threading.Monitor.Exit(ownership); }
  }
  internal static bool Hex(string value){if(value==null||value.Length!=64)return false;foreach(char c in value)if(!((c>='a'&&c<='f')||(c>='0'&&c<='9')))return false;return true;}
  private static string ToHex(byte[] bytes){return BitConverter.ToString(bytes).Replace("-","").ToLowerInvariant();}
 }
 internal sealed class SystemAnchorFailure:Exception {
  internal SystemAnchorFailure(Exception cause):base("host_port_os_anchor_rejected",cause){}
  public override string ToString(){return "host_port_os_anchor_rejected";}
 }
 internal sealed class SystemAnchorCleanupFailure:Exception {
  private readonly SystemAnchorAdmission owner;
  internal SystemAnchorCleanupFailure(SystemAnchorAdmission actual,Exception primary,Exception cleanup):base("host_port_os_anchor_cleanup_failed",new AggregateException(primary==null?new[]{cleanup}:new[]{primary,cleanup})){owner=actual;}
  internal SystemAnchorAdmission Owner { get {return owner;} }
  public override string ToString(){return "host_port_os_anchor_cleanup_failed";}
 }
 internal static class SystemNative {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,EntryPoint="GetWindowsDirectoryW")]internal static extern uint GetWindowsDirectory([Out]char[] name,uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,EntryPoint="GetModuleFileNameW")]internal static extern uint GetModuleFileName(IntPtr module,[Out]char[] name,uint size);
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct TrustFile { internal uint Size;[MarshalAs(UnmanagedType.LPWStr)]internal string Path;internal IntPtr Handle,Subject; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct TrustData { internal uint Size;internal IntPtr Policy,SIP;internal uint UI,Revocation,Union;internal IntPtr File;internal uint StateAction;internal IntPtr State,URL;internal uint Flags,UIContext; }
  [DllImport("wintrust.dll",ExactSpelling=true,PreserveSig=true)]private static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
  internal static bool SignatureValid(string fixedPath) {
   TrustFile file=new TrustFile{Size=(uint)Marshal.SizeOf(typeof(TrustFile)),Path=fixedPath};IntPtr memory=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TrustFile)));bool initialized=false;
   TrustData data=new TrustData{Size=(uint)Marshal.SizeOf(typeof(TrustData)),UI=2,Union=1,File=memory,StateAction=0,Revocation=1,Flags=0x1000};Guid action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
   try { Marshal.StructureToPtr(file,memory,false);initialized=true;return WinVerifyTrust(new IntPtr(-1),ref action,ref data)==0; }
   finally { if(initialized)Marshal.DestroyStructure(memory,typeof(TrustFile));Marshal.FreeHGlobal(memory); }
  }
 }
}
