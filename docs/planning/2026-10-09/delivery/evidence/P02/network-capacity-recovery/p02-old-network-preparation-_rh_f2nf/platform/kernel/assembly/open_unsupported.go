//go:build !linux && !darwin

package assembly

import (
	"errors"
	"os"
)

func openMemberFile(root *os.Root,entry string)(*os.File,error){
	return nil,errors.New("protected member opening is unsupported on this platform")
}
