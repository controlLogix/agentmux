package main
import("encoding/json";"os";"github.com/controlLogix/agentmux/platform/deployment")
func main(){var s deployment.ComposeSpec;if json.NewDecoder(os.Stdin).Decode(&s)!=nil{os.Exit(2)};b,e:=deployment.RenderCompose(s);if e!=nil{os.Exit(3)};_,_=os.Stdout.Write(b)}
