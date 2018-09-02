package wire

import (
	"io"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"bytes"
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
type Message interface {
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
	// 读取并解析消息头用我们已经封装好的方法。
	// io.Reader实际上是net.Conn对象，也就是TCP socket
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
	//检查checksum.对payload进行hash校验，看payload是否被修改过
	checksum := chainhash.DoubleHashB(payload)[0:4]
	if !bytes.Equal(checksum[:], hdr.checksum[:]) {
		str := fmt.Sprintf("payload checksum failed - header "+
			"indicates %v, but actual checksum is %v.",
			hdr.checksum, checksum)
		return totalBytes, nil, nil, messageError("ReadMessage", str)
	}
	pr := bytes.NewBuffer(payload)
	// 用Message的抽象方法BtcDecode()对消息体进行解析
	err = msg.BtcDecode(pr,pver)
	if err != nil {
		return totalBytes, nil, nil, err
	}
	// msg中已经包含了messageHeader，payload是有效载荷，messageHeader辅助读取，验证等
	return totalBytes, msg, payload, nil  
	
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

func WriteMessageWithEncodingN(w io.Writer, msg Message, pver uint32,
	btcnet BitcoinNet, encoding MessageEncoding) (int, error) {

	totalBytes := 0

	// Enforce max command size.
	var command [CommandSize]byte
	cmd := msg.Command()
	if len(cmd) > CommandSize {
		str := fmt.Sprintf("command [%s] is too long [max %v]",
			cmd, CommandSize)
		return totalBytes, messageError("WriteMessage", str)
	}
	copy(command[:], []byte(cmd))

	// Encode the message payload.
	var bw bytes.Buffer
	err := msg.BtcEncode(&bw, pver, encoding)
	if err != nil {
		return totalBytes, err
	}
	payload := bw.Bytes()
	lenp := len(payload)

	// Enforce maximum overall message payload.
	if lenp > MaxMessagePayload {
		str := fmt.Sprintf("message payload is too large - encoded "+
			"%d bytes, but maximum message payload is %d bytes",
			lenp, MaxMessagePayload)
		return totalBytes, messageError("WriteMessage", str)
	}

	// Enforce maximum message payload based on the message type.
	mpl := msg.MaxPayloadLength(pver)
	if uint32(lenp) > mpl {
		str := fmt.Sprintf("message payload is too large - encoded "+
			"%d bytes, but maximum message payload size for "+
			"messages of type [%s] is %d.", lenp, cmd, mpl)
		return totalBytes, messageError("WriteMessage", str)
	}

	// Create header for the message.
	hdr := messageHeader{}
	hdr.magic = btcnet
	hdr.command = cmd
	hdr.length = uint32(lenp)
	copy(hdr.checksum[:], chainhash.DoubleHashB(payload)[0:4])

	// Encode the header for the message.  This is done to a buffer
	// rather than directly to the writer since writeElements doesn't
	// return the number of bytes written.
	hw := bytes.NewBuffer(make([]byte, 0, MessageHeaderSize))
	writeElements(hw, hdr.magic, command, hdr.length, hdr.checksum)

	// Write header.
	n, err := w.Write(hw.Bytes())
	totalBytes += n
	if err != nil {
		return totalBytes, err
	}

	// Write payload.
	n, err = w.Write(payload)
	totalBytes += n
	return totalBytes, err
}

















