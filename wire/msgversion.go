package wire

import "time"

type MsgVersion struct{
	ProtocolVersion int32
	Services ServiceFlag
	Timestamp time.Time
	AddrYou NetAddress
	AddrMe NetAddress
	Nonce uint64
	UserAgent string
	LastBlock int32
	DisableRelayTx bool
}

func (msg *MsgVersion)BtcEecode(w io.Writer,pver uint32)error{
	err := validateUserAgent(msg.UserAgent)
	if err != nil{
		return err
	}
	err = writeElements(w,msg.ProtocolVersion,msg.Services,msg.Timestamp.Uinx())
	if err != nil {
		return err
	}
	
	err = writeNetAddress(w,pver,&msg.AddrYou,false)
	if err != nil {
		return 
	}
	
	err = writeNetAddress(w,pver,&msg.AddrMe,false)
	if err != nil {
		return 
	}
	
	err = writeElement(w,msg.Nonce)
	if err != nil {
		return 
	}
	
	err = WriteVarString(w, pver, msg.UserAgent)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.LastBlock)
	if err != nil {
		return err
	}

	return writeElement(w, !msg.DisableRelayTx)
	
}

























