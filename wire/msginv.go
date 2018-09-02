package wire
//inv主要用来向Peer通知区块或者交易数据
// 它是getblocks消息的响应消息，也可以主动发送。
// inv消息体包含一个InvVect列表和表示InvVect个数的可变长度整数Count值
type MsgInv struct{
	InvList []*InvVect
}
