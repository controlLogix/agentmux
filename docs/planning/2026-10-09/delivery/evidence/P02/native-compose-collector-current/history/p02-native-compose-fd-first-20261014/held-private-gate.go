package main
import (
 "fmt"
 "os"
 "strconv"
 "strings"
 "github.com/controlLogix/agentmux/platform/privatefs"
)
func main() {
 if len(os.Args) < 3 { os.Exit(2) }
 for _, arg := range os.Args[1:] {
  kind, number, ok := strings.Cut(arg, "=")
  fd, err := strconv.Atoi(number)
  if !ok || err != nil || fd < 3 { os.Exit(2) }
  access := privatefs.PublicAncestor
  if kind == "private" { access = privatefs.PrivateObject } else if kind != "ancestor" { os.Exit(2) }
  file := os.NewFile(uintptr(fd), "held-qualification-descriptor")
  if file == nil || privatefs.CheckDescriptor(file, access) != nil { os.Exit(3) }
 }
 fmt.Println("held_private_access_admitted")
}
