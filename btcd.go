package main
import (
	"os"
)
func main(){
	if err := btcdMain(nil);err != nil {
		os.Exit(1)
	}
}
func btcdMain() error {

}