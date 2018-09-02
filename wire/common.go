package wire
import (
	"io"
	"encoding/binary"
	"time"
	"math"
)
const (
	// MaxVarIntPayload is the maximum payload size for a variable length integer.
	MaxVarIntPayload = 9

	// binaryFreeList 缓从的个数
	binaryFreeListMaxItems = 1024
)
var (
	// binaryFreeList中数值和字节之间转化时需要用到
	littleEndian = binary.LittleEndian
	bigEndian = binary.BigEndian
)
var errNonCanonicalVarInt = "non-canonical varint %x - discriminant %x must " +
	"encode a value greater than %x"
// binaryFreeList :是用作一个缓冲队列
type binaryFreeList chan []byte
// 从缓冲队列binaryFreeList中借8个字节
func (l binaryFreeList)Borrow() []byte{
	var buf []byte
	select {
	case buf = <- l:
	default:
		buf = make([]byte,8)
	}
	return buf[:8]
}
// 给binaryFreeList归还字节
func (l binaryFreeList) Return (buf []byte){
	select {
		case l <- buf:
		default:
		// 写不进去，说明binaryFreeList已经满了，那就让它等着垃圾回收吧
	}
}
// 从io.Reader中读取一个uint8
func (l binaryFreeList) Uint8(r io.Reader)(uint8,error){
	buf := l.Borrow()[:1]
	// 从r中读取数据到buf中。返会的是读取的长度n,这里不需要这个返会值。
	// 因为既然已经是uint8了，肯定会读满buf的。n就是1
	if _,err := io.ReadFull(r,buf);err != nil{
		l.Return(buf)
		return 0, err
	}
	rv := buf[0]
	l.Return(buf)
	return rv,nil
}
// 从io.Reader中读取一个uint16,这个和上面uint8类似，多了一个byteOrder
// binary包：实现了简单的数字与字节序列的转换，已经变长值的编解码

func(l binaryFreeList) Uint16(r io.Reader,byteOrder binary.ByteOrder)(uint16,error){
	buf := l.Borrow()[:2]
	if _,err := io.ReadFull(r,buf);err != nil{
		l.Return(buf)
		return 0,nil
	}
	rv := byteOrder.Uint16(buf)
	l.Return(buf)
	return rv,nil
}
func(l binaryFreeList) Uint32(r io.Reader,byteOrder binary.ByteOrder)(uint32,error){
	buf := l.Borrow()[:4]
	if _,err := io.ReadFull(r,buf);err != nil{
		l.Return(buf)
		return 0,nil
	}
	rv := byteOrder.Uint32(buf)
	l.Return(buf)
	return rv,nil
}
func(l binaryFreeList) Uint64(r io.Reader,byteOrder binary.ByteOrder)(uint64,error){
	buf := l.Borrow()[:8]
	if _,err := io.ReadFull(r,buf);err != nil{
		l.Return(buf)
		return 0,nil
	}
	rv := byteOrder.Uint64(buf)
	l.Return(buf)
	return rv,nil
}

// 把一个uint8转化成自己数据写入到io.Writer
// 和上面的读是相反的过程
func (l binaryFreeList) PutUint8(w io.Writer,val uint8) error{
	buf := l.Borrow()[:1]
	buf[0] = val
	_,err := w.Write(buf)
	l.Return(buf)
	return err
}

func (l binaryFreeList) PutUint16(w io.Writer,byteOrder binary.ByteOrder,val uint16) error{
	buf := l.Borrow()[:2]
	byteOrder.PutUint16(buf,val)
	_,err := w.Write(buf)
	l.Return(buf)
	return err
}
func (l binaryFreeList) PutUint32(w io.Writer,byteOrder binary.ByteOrder,val uint32) error{
	buf := l.Borrow()[:4]
	byteOrder.PutUint32(buf,val)
	_,err := w.Write(buf)
	l.Return(buf)
	return err
}
func (l binaryFreeList) PutUint64(w io.Writer,byteOrder binary.ByteOrder,val uint64) error{
	buf := l.Borrow()[:8]
	byteOrder.PutUint64(buf,val)
	_,err := w.Write(buf)
	l.Return(buf)
	return err
}

var binarySerializer binaryFreeList = make(chan []byte,binaryFreeListMaxItems)
// uint32Time represents a unix timestamp encoded with a uint32.  It is used as
// a way to signal the readElement function how to decode a timestamp into a Go
// time.Time since it is otherwise ambiguous.
type uint32Time time.Time

// int64Time represents a unix timestamp encoded with an int64.  It is used as
// a way to signal the readElement function how to decode a timestamp into a Go
// time.Time since it is otherwise ambiguous.
type int64Time time.Time

func readElement(r io.Reader,element interface{}) error{
	switch e:= element.(type){
	case *int32:
		rv,err := binarySerializer.Uint32(r,littleEndian)
		if err != nil {
			return err
		}
		*e = int32(rv)  //rv是uint32，转化成int32
		return nil
	case *uint32:
		rv,err := binarySerializer.Uint32(r,littleEndian)
		if err != nil {
			return err
		}
		*e = rv
		return nil
	case *int64:
		rv,err := binarySerializer.Uint64(r,littleEndian)
		if err != nil {
			return err
		}
		*e = int64(rv) 
		return nil
	case *uint64:
		rv,err := binarySerializer.Uint64(r,littleEndian)
		if err != nil {
			return err
		}
		*e = rv
		return nil
	case *bool:
		rv,err := binarySerializer.Uint8(r)
		if err != nil {
			return err
		}
		if rv == 0x00 {
			*e =false
		}else{
			*e =true
		}
		return nil
	case *uint32Time:
		rv,err := binarySerializer.Uint32(r,binary.LittleEndian)	//rv现在是uint32的数字
		if err != nil{
			return nil
		}
		*e = uint32Time(time.Unix(int64(rv),0))
		return nil
	case *int64Time:
		rv, err := binarySerializer.Uint64(r, binary.LittleEndian)
		if err != nil {
			return err
		}
		*e = int64Time(time.Unix(int64(rv), 0))
		return nil
	// Message header checksum.
	case *[4]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	// Message header command.
	case *[CommandSize]uint8:
		_, err := io.ReadFull(r, e[:]) //直接给你读到e中
		if err != nil {
			return err
		}
		return nil
	}
	// 未完待续
	
	
	// 上面都不满足，才执行此句
	return binary.Read(r,littleEndian,element)
}

func readElements(r io.Reader,elements ...interface{}) error{
	for _,element := range elements{
		err := readElement(r,element)
		if err != nil{
			return err
		}
	}
	return nil
}

// readElement的反过程
// 就是把element编码成字节然后写入到w中
func writeElement(w io.Writer, element interface{}) error {
	//需要补充
	
}
func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}

//除了基础数据类型，为了压缩传输数据量，bitcoin协议定义了可变长度整数值，
//通过可变长度整数值的序列化方法WriteVarInt()来理解
// 就是根据val的不同大小，有不同的序列话方法。
// 往w中写入的时候，现在写入了一个标识类型的1字节。例如uint16就先写入0xfd，uint32就先写入0xfe
// 这样读取的时候，判断先读出的1字节，就知道后面的类型了
func WriteVarInt(w io.Writer,pver uint32,val uint64)error{
	if val < 0xfd{
		return binarySerializer.PutUint8(w,uint8(val))
	}
	if val <= math.MaxUint16{
		err := binarySerializer.PutUint8(w,0xfd)
		if err != nil{
			return err
		}
		return binarySerializer.PutUint16(w,littleEndian,uint16(val))
	}
	if val <= math.MaxUint32{
		err := binarySerializer.PutUint8(w,0xfe)
		if err != nil{
			return err
		}
		return binarySerializer.PutUint32(w.littleEndian,uint32(val))
	}
	err := binarySerializer.PutUint8(w,0xff)
	if err != nil{
		return err
	}
	return binarySerializer.PutUint64(w,littleEndian,val)
}
// writeVarInt的逆过程
func ReadVarInt(r io.Reader, pver uint32) (uint64, error){
	// 从Reader中读取一个字节
	discriminant,err := binarySerializer.Uint8(r)
	if err != nil{
		return 0,err
	}
	var rv uint64
	switch discriminant{
	case 0xff:
		sv,err := binarySerializer.Uint64(r,littleEndian)
		if err != nil{
			return 0,err
		}
		rv = sv
		min := uint64(0x100000000)
		// 相当于一个二次判断。看他这个值到底值不值得uint64编码
		if rv < min {
			return 0, messageError("ReadVarInt", fmt.Sprintf(
				errNonCanonicalVarInt, rv, discriminant, min))
		}
	case 0xfe:
		sv, err := binarySerializer.Uint32(r, littleEndian)
		if err != nil {
			return 0, err
		}
		rv = uint64(sv)

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		min := uint64(0x10000)
		if rv < min {
			return 0, messageError("ReadVarInt", fmt.Sprintf(
				errNonCanonicalVarInt, rv, discriminant, min))
		}

	case 0xfd:
		sv, err := binarySerializer.Uint16(r, littleEndian)
		if err != nil {
			return 0, err
		}
		rv = uint64(sv)

		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		min := uint64(0xfd)
		if rv < min {
			return 0, messageError("ReadVarInt", fmt.Sprintf(
				errNonCanonicalVarInt, rv, discriminant, min))
		}
	default:
		rv := uint64(discriminant)
	}
	return rv,nil  //最后的返会值，还是uint64的
}








