//go:build linux || darwin

package assembly

import (
	"errors"
	"os"
	"syscall"
)

func openMemberFile(root *os.Root,entry string)(*os.File,error){
	f,err:=root.OpenFile(entry,os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,0)
	if err!=nil {return nil,err}
	info,err:=f.Stat()
	if err!=nil || !info.Mode().IsRegular() {f.Close();return nil,errors.New("member is not a regular file")}
	return f,nil
}
