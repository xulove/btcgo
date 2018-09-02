package wire

import "time"

type MsgBlock struct {
	Header       BlockHeader
	Transactions []*MsgTx
}
type BlockHeader struct {
	// 区块的版本，与协议版本号不同
	Version int32
	// 链上前一个区块的Hash值，每个区块都通过该字段指向上一个区块，直到创世区块，从而形成链结构
	PrevBlock chainhash.Hash
	// Merkle树的树根Hash，包含了区块中所有交易的信息的hash值。
	MerkleRoot chainhash.Hash
	// 区块创建的时间点
	Timestamp time.Time
	// 挖矿的难度
	Bits uint32
	// 用于挖矿或验证区块难度的随机值
	Nonce uint32
}
