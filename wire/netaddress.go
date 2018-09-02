package wire

import (
	"time"
	"net"
)
type NetAddress struct{
	Timestamp time.Time
	Services ServiceFlag
	IP net.IP
	Port uint16
}

func writeNetAddress(w io.Writer,pver uint32,na *NetAddress,ts bool) error{
	if ts&& pver>= NetAddressTimeVersion{
		err := writeElement(w,uint32(na.Timestamp.Unix()))
		if err != nil {
			return err
		}
	}
	var ip [16]byte
	if na.IP != nil {
		copy(ip[:],na.IP.To16())
	}
	err := writeElements(w,na.Services,ip)
	if err != nil{
		return err
	}
	return binary.Write(w, bigEndian, na.Port)
}





































