package launcher

import (
 "io"
 "os"
)

func composeCLIMidBootBoundedEnvironment(path string)(data []byte,readErr,closeErr error){
 file,openErr:=os.Open(path)
 if openErr!=nil{return nil,openErr,nil}
 data,readErr=io.ReadAll(io.LimitReader(file,64*1024+1))
 closeErr=file.Close()
 return data,readErr,closeErr
}
