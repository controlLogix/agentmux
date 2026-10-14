package main
import (
 "fmt"
 "os"
 "strconv"
 "strings"
 "syscall"
 "github.com/controlLogix/agentmux/platform/privatefs"
)
func main() {
 args := os.Args[1:]
 if len(args) < 3 { os.Exit(2) }
 for index, arg := range args {
  kind, number, ok := strings.Cut(arg, "=")
  fd, err := strconv.Atoi(number)
  if !ok || err != nil || fd < 3 { os.Exit(2) }
  expectedKind := "ancestor"
  if index >= len(args)-2 { expectedKind = "private" }
  if kind != expectedKind { os.Exit(2) }
  access := privatefs.PublicAncestor
  if kind == "private" { access = privatefs.PrivateObject } else if kind != "ancestor" { os.Exit(2) }
  file := os.NewFile(uintptr(fd), "held-qualification-descriptor")
  if file == nil { os.Exit(3) }
  info, err := file.Stat()
  if err != nil { os.Exit(3) }
  held, ok := info.Sys().(*syscall.Stat_t)
  if !ok || info.Mode() & (os.ModeSetuid | os.ModeSetgid) != 0 { os.Exit(3) }
  if index == len(args)-1 {
   if !info.Mode().IsRegular() || held.Nlink != 1 { os.Exit(3) }
  } else if !info.IsDir() { os.Exit(3) }
  if kind == "private" {
   if held.Uid != uint32(os.Geteuid()) || info.Mode().Perm() & 0077 != 0 { os.Exit(3) }
  } else if (held.Uid != 0 && held.Uid != uint32(os.Geteuid())) || info.Mode().Perm() & 0022 != 0 { os.Exit(3) }
  if privatefs.CheckDescriptor(file, access) != nil { os.Exit(3) }
 }
 fmt.Println("held_private_access_admitted")
}
