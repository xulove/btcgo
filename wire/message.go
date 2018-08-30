package wire

import (
	"io"
)
// 消息头的字节长度
const MessageHeaderSize = 24
// MessageEncoding represents the wire message encoding format to be used.
type MessageEncoding uint32

const (
	// BaseEncoding encodes all messages in the default format specified
	// for the Bitcoin wire protocol.
	BaseEncoding MessageEncoding = 1 << iota

	// WitnessEncoding encodes all messages other than transaction messages
	// using the default Bitcoin wire protocol specification. For transaction
	// messages, the new encoding format detailed in BIP0144 will be used.
	WitnessEncoding
)
type message interface {
	BtcDecode(io.Reader,uint32,MessageEncoding)error
	BtcEncode(io.Writer,uint32,MessageEncoding)error
	Command() string
	MaxPayloadLength(uint32)uint32
}
type messageHeader struct {
	magic BitcoinNet   //4bytes 例如：主网main的Magic值：F9BEB4D9
	command string  //12bytes
	lenght uint32  //4 bytes
	checksum [4]byte //4 bytes
}

// 在common.go中，我们定义了readElement(),
// 在此基础上，我们可以完成readMessage()

func ReadMessage(r io.Reader,pver uint32,btcnet BitcoinNet)(Message,[]byte,error){
	_,msg,buf,err := ReadMessageN(r,pver,btcnet)
	return msg,buf,err
}
func ReadMessageN(r io.Reader,pver uint32,btcnet BitcoinNet)(int,Message,[]byte,error){
	return ReadMessageWithEncodingN(r,pver,btcnet,BaseEncoding)
}
func ReadMessageWithEncodingN(r io.Reader, pver uint32, btcnet BitcoinNet,enc MessageEncoding) (int, Message, []byte, error){
	totalBytes := 0
	n,hdr,err := readMessageHeader(r)
	totalBytes += n
	if err != nil{
		return totalBytes,nil,nil,err
	}
	// 从消息头的lenght字段判断data是否超过了允许的最大值
	if hdr.length > MaxMessagePayload {
		str := fmt.Sprintf("message payload is too large - header "+
			"indicates %d bytes, but max message payload is %d "+
			"bytes.", hdr.length, MaxMessagePayload)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}
	// 从消息头的magic字段，判断是否是同一网络
	if hdr.magic != btcnet {
		discardInput(r, hdr.length)
		str := fmt.Sprintf("message from other network [%v]", hdr.magic)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}
	command := hdr.command
	// utf8包实现了对utf-8文本的常用函数和常数的支持，包括rune和utf-8编码byte序列之间互相翻译的函数
	// ValidString() :报告s是否包含完整且合法的utf-8编码序列
	if !urf8.ValidString(command){
		// 舍弃后面的一段bytes，其实就是真正的data。Payload
		discardInput(r, hdr.length)
		str := fmt.Sprintf("invalid command %v", []byte(command))
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}
	// 根据command的类型创建message结构体
	msg，err := makeEmptyMessage(command)
	if err != nil {
		discardInput(r, hdr.length)
		return totalBytes, nil, nil, messageError("ReadMessage",
			err.Error())
	}
	
	mpl := msg.MaxPayloadLength(pver)
	if hdr.length > mpl{
		discardInput(r, hdr.length)
		str := fmt.Sprintf("payload exceeds max length - header "+
			"indicates %v bytes, but max payload size for "+
			"messages of type [%v] is %v.", hdr.length, command, mpl)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}
	
	// 上面已经读取了MessageHeader了，现在开始读取payload（有效载荷）
	payload := make([]byte,hdr.length)
	n,err = io.ReadFull(r,payload)
	totalBytes += n
	if err != nil {
		return totalBytes,nil,nil,err
	}
	//检查checksum
	checksum := chainhash.DoubleHashB(payload)[0:4]
	if !bytes.Equal(checksum[:], hdr.checksum[:]) {
		str := fmt.Sprintf("payload checksum failed - header "+
			"indicates %v, but actual checksum is %v.",
			hdr.checksum, checksum)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}
	pr := bytes.NewBuffer(payload)
	err = mag.BtcDecode(pr,pver,enc)
	if err != nil {
		return totalBytes, nil, nil, err
	}
	
	return totalBytes, msg, payload, nil  
	// 为什么这里只返会了msg，msg才是有效载荷，messageHeader辅助读取，验证等
} 
func readMessageHeader(r io.Reader)(int,*messageHeader,error){
	var headerBytes [MessageHeaderSize]byte
	n,err := io.ReadFull(r,headerBytes[:])
	if err != nil{
		return n,nil,err
	}
	hr := bytes.NewReader(headerBytes[:])
	
	hdr := messageHeader{}
	readElements(hr,&hdr.magic,&command,&hdr.length,&hdr.checksum)
	
	hdr.command = string(bytes.TrimRight(command[:],string(0)))
	return n,&hdr,nil
}



















