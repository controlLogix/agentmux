// This binary is compiled only to verify rejection of dynamic dependencies.
package main

/*
#include <stdio.h>
*/
import "C"

func main() { C.putchar(0) }
