package wire

const MaxBlockLocatorsPerMsg = 500
//getblocks请求的区块位于BlockLocator指向的区块和HashStop指向的区块之间，不包括BlockLocator指向的区块。
// 如果HashStop为零，则返回BlockLocator指向的区块之后的500个区块。当然需要理解BlockLocator：
//BlockLocator实际是一个*chainhash.Hash类型的slice，用于记录一组block的hash值，slice中的第一个元素即BlockLocator指向的区块。
// 区块链可能分叉，为了致命该区块的位置，BlockLocator记录了从指定区块回溯到创世区块的路径。
// BlockLocator中的前10个hash值是一个接着一个的区块hash值，
// 第11个元素后步长成级数增加，即每一次向前回溯，步长翻倍，加速向创世区块回溯，保证了BlockLocator中元素并不是很多。
type MsgGetBlocks struct{
	ProtocolVersion uint32
	BlockLocatorHashes []*chainhash.Hash
	HashStop chainhash.Hash
}

func (msg *MsgGetBlocks) BtcEncode(w  io.Writer,pver uint32,enc MessageEncoding)error{
	count := len(msg.BlockLocatorHashes)
	if count>MaxBlockLocatorsPerMsg{
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.BtcEncode", str)
	}
	err := writeElements(w,msg.ProtocolVersion)
	if err != nil{
		return err
	}
	err = writeVarInt(w,pver,uint64(count))
	for _,hash := range msg.BlockLocatorHashes{
		err = writeElement(w, hash)
		if err != nil {
			return err
		}
	}
	return writeElement(w, &msg.HashStop)
}
func (msg *MsgGetBlocks) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := readElement(r, &msg.ProtocolVersion)
	if err != nil {
		return err
	}

	// Read num block locator hashes and limit to max.
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.BtcDecode", str)
	}

	// Create a contiguous slice of hashes to deserialize into in order to
	// reduce the number of allocations.
	locatorHashes := make([]chainhash.Hash, count)
	msg.BlockLocatorHashes = make([]*chainhash.Hash, 0, count)
	for i := uint64(0); i < count; i++ {
		hash := &locatorHashes[i]
		err := readElement(r, hash)
		if err != nil {
			return err
		}
		msg.AddBlockLocatorHash(hash)
	}

	return readElement(r, &msg.HashStop)
}




























