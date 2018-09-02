package wire

type MsgTx struct {
	Version  int32      //Tx的版本号，
	TxIn     []*TxIn    //引用的输入交易的UTXO(s),包含上一个交易的hash值和index
	TxOut    []*TxOut   //当前交易的输出UTXO(s)
	LockTime uint32     //既可以表示UTC时间，也可以表示区块高度。
}

type TxIn struct {
	PreviousOutPoint OutPoint   //其中的Index即是前一个交易的[]*TxOut中的索引号
	SignatureScript  []byte     //解锁脚本
	Witness          TxWitness  //TxWitness定义TxIn的见证。见证者将被解释为一片字节片，或者是一个或多个元素的堆栈
	Sequence         uint32     //输入交易的序号，对于同一个交易，矿工优先选择Sequence更大的交易加入区块进行挖矿
}

type TxOut struct {
	Value    int64      //bitcoin数量，单位是聪
	PkScript []byte     //解锁脚本
}

// OutPoint定义了一个用于追踪以前交易输出的比特币数据类型.
type OutPoint struct {
	Hash  chainhash.Hash    //上一个交易的hash值
	Index uint32            //表示上一个交易的输出的序号
}

