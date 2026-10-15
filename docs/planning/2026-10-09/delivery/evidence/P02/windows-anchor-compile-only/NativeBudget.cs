using System;
using System.Diagnostics;

namespace Agentmux.SelectedHost {
 // One entry-created budget is passed through validation, spawn, pipe IO and
 // cleanup. No nested method creates a fresh operation allowance.
 internal sealed class NativeBudget {
  private readonly long deadline;
  internal NativeBudget(int originalRemainingMilliseconds) {
   if(originalRemainingMilliseconds<1 || originalRemainingMilliseconds>5000) throw new InvalidOperationException("host_port_deadline");
   deadline=Stopwatch.GetTimestamp()+(long)Math.Ceiling(originalRemainingMilliseconds*Stopwatch.Frequency/1000.0);
  }
  internal int Remaining {
   get { long left=deadline-Stopwatch.GetTimestamp();if(left<=0)return 0;return (int)Math.Min(Int32.MaxValue,Math.Floor(left*1000.0/Stopwatch.Frequency)); }
  }
  internal void Check() { if(Remaining<1) throw new InvalidOperationException("host_port_deadline"); }
 }
}
