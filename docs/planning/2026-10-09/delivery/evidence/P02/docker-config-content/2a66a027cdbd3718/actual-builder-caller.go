package main
import("encoding/json";"os";"github.com/controlLogix/agentmux/platform/kernel/communication")
func main(){var in struct{Hub string;Credentials communication.Credentials};if json.NewDecoder(os.Stdin).Decode(&in)!=nil{os.Exit(2)};b,e:=communication.BuildConfigWithListener(in.Hub,communication.Listener{Mode:communication.ContainerInternal,Port:4222},in.Credentials);if e!=nil{os.Exit(3)};_,_=os.Stdout.Write(b)}
