package peer

import (
	"net"
	"sync"
	"time"
	"github.com/btcsuite/btcgo/logo"
	"github.com/btcsuite/btcd/wire"
	"fmt"
	"errors"
)
type Peer struct {
	// The following variables must only be used atomically.
	bytesReceived uint64
	bytesSent     uint64
	lastRecv      int64
	lastSend      int64
	connected     int32
	disconnect    int32

	conn net.Conn

	// 这些字段在创建时设置并且从不修改，因此它们可安全地在没有互斥锁的情况下同时读取
	addr    string
	cfg     Config
	inbound bool

	flagsMtx             sync.Mutex // protects the peer flags below
	na                   *wire.NetAddress
	id                   int32
	userAgent            string
	services             wire.ServiceFlag
	versionKnown         bool
	advertisedProtoVer   uint32 // protocol version advertised by remote
	protocolVersion      uint32 // negotiated protocol version
	sendHeadersPreferred bool   // peer sent a sendheaders message
	verAckReceived       bool
	witnessEnabled       bool

	wireEncoding wire.MessageEncoding

	knownInventory     *mruInventoryMap
	prevGetBlocksMtx   sync.Mutex
	prevGetBlocksBegin *chainhash.Hash
	prevGetBlocksStop  *chainhash.Hash
	prevGetHdrsMtx     sync.Mutex
	prevGetHdrsBegin   *chainhash.Hash
	prevGetHdrsStop    *chainhash.Hash

	// These fields keep track of statistics for the peer and are protected
	// by the statsMtx mutex.
	statsMtx           sync.RWMutex
	timeOffset         int64
	timeConnected      time.Time
	startingHeight     int32
	lastBlock          int32
	lastAnnouncedBlock *chainhash.Hash
	lastPingNonce      uint64    // Set to nonce if we have a pending ping.
	lastPingTime       time.Time // Time we sent last ping.
	lastPingMicros     int64     // Time for last ping to return.

	stallControl  chan stallControlMsg
	outputQueue   chan outMsg
	sendQueue     chan outMsg
	sendDoneQueue chan struct{}
	outputInvChan chan *wire.InvVect
	inQuit        chan struct{}
	queueQuit     chan struct{}
	outQuit       chan struct{}
	quit          chan struct{}
}

type Config struct {
	// NewestBlock指定一个回调方法，此方法能根据需求从其他节点提供最新的区块细节。
	// 当然可能请求到一个块高度为0的区块，返回的是nil，然而大部分好的情况是返回准确的区块细节。
	NewestBlock HashFunc
	// HostToNetAddress方法给指定的host返回网络地址NetAddress，这个地址可能是nil，大部分情况会解析成一个IP地址
	HostToNetAddress HostToNetAddrFunc
	// Proxy表面连接用到了代理。这样做的唯一后果是防止泄漏tor代理地址，也就是说只有使用tor代理时才指定Proxy。
	Proxy string
	// 为版本发行指定用户代理名称。我们强烈建议指定这个值。
	UserAgentName string
	// 为版本发行指定版本号。我们强烈建议指定这个值，遵循 "major.minor.revision" e.g. "2.6.41" 。
	UserAgentVersion string
	// 为版本发行指定评论语，但不能使用非法的字符在里面，比如  '/', ':', '(', ')'.
	UserAgentComments []string
	// ChainParams，链参数，主要指定通信的节点要在哪条链上沟通以及如何沟通。如果忽略掉这个参数，测试网络将会被使用。
	ChainParams *chaincfg.Params
	// 指定由本地节点提供给发行版本哪个服务。如果忽略掉这个参数，将是0，因此没有本地节点提供服务。
	Services wire.ServiceFlag
	// 指定发行版本的最大协议版本。如果忽略这个参数，将使用peer.MaxProtocalVersion的值。
	ProtocolVersion uint32
	// 指定远程节点应当被告知不要为了transactions发送inv meesages。
	DisableRelayTx bool
	// 接收到节点的消息时，启动回调函数
	Listeners MessageListeners
}

type MessageListeners struct {
	// 当收到一个getaddr的比特币消息时启动此方法
	OnGetAddr func(p *Peer, msg *wire.MsgGetAddr)
	// 当收到一个addr的比特币消息时启动该方法
	OnAddr func(p *Peer, msg *wire.MsgAddr)
	// 当一个节点收到一个ping的比特币消息时启动该方法
	OnPing func(p *Peer, msg *wire.MsgPing)
	// 当一个节点收到一个pong的比特币消息时启动该方法
	OnPong func(p *Peer, msg *wire.MsgPong)
	// 当一个节点收到一个alert的比特币消息时启动该方法
	OnAlert func(p *Peer, msg *wire.MsgAlert)
	// 当一个节点收到一个mempool的比特币消息时启动该方法
	OnMemPool func(p *Peer, msg *wire.MsgMemPool)
	// 当一个节点收到一个tx的比特币消息时启动该方法
	OnTx func(p *Peer, msg *wire.MsgTx)
	// 当一个节点收到一个block的比特币消息时启动该方法
	OnBlock func(p *Peer, msg *wire.MsgBlock, buf []byte)
	// 当一个节点收到一个cfilter的比特币消息时启动该方法
	OnCFilter func(p *Peer, msg *wire.MsgCFilter)
	// 当一个节点收到一个cfheaders的比特币消息时启动该方法
	OnCFHeaders func(p *Peer, msg *wire.MsgCFHeaders)
	// 当一个节点收到一个cfcheckpt的比特币消息时启动该方法
	OnCFCheckpt func(p *Peer, msg *wire.MsgCFCheckpt)
	// 当一个节点收到一个inv的比特币消息时启动该方法
	OnInv func(p *Peer, msg *wire.MsgInv)
	// 当一个节点收到一个headers的比特币消息时启动该方法
	OnHeaders func(p *Peer, msg *wire.MsgHeaders)
	// 当一个节点收到一个notfound的比特币消息时启动该方法
	OnNotFound func(p *Peer, msg *wire.MsgNotFound)
	// 当一个节点收到一个getdata的比特币消息时启动该方法
	OnGetData func(p *Peer, msg *wire.MsgGetData)
	// 当一个节点收到一个getblocks的比特币消息时启动该方法
	OnGetBlocks func(p *Peer, msg *wire.MsgGetBlocks)
	// 当一个节点收到一个getheaders的比特币消息时启动该方法
	OnGetHeaders func(p *Peer, msg *wire.MsgGetHeaders)
	// 当一个节点收到一个getcfilters的比特币消息时启动该方法
	OnGetCFilters func(p *Peer, msg *wire.MsgGetCFilters)
	// 当一个节点收到一个getcfheaders的比特币消息时启动该方法
	OnGetCFHeaders func(p *Peer, msg *wire.MsgGetCFHeaders)
	// 当一个节点收到一个getcfcheckpt的比特币消息时启动该方法
	OnGetCFCheckpt func(p *Peer, msg *wire.MsgGetCFCheckpt)
	// 当一个节点收到一个feefilter的比特币消息时启动该方法
	OnFeeFilter func(p *Peer, msg *wire.MsgFeeFilter)
	// 当一个节点收到一个filteradd的比特币消息时启动该方法
	OnFilterAdd func(p *Peer, msg *wire.MsgFilterAdd)
	// 当一个节点收到一个filterclear的比特币消息时启动该方法
	OnFilterClear func(p *Peer, msg *wire.MsgFilterClear)
	// 当一个节点收到一个filterload的比特币消息时启动该方法
	OnFilterLoad func(p *Peer, msg *wire.MsgFilterLoad)
	// 当一个节点收到一个merkleblock的比特币消息时启动该方法
	OnMerkleBlock func(p *Peer, msg *wire.MsgMerkleBlock)
	// 当一个节点收到一个version的比特币消息时启动该方法
	OnVersion func(p *Peer, msg *wire.MsgVersion)
	// 当一个节点收到一个verack的比特币消息时启动该方法
	OnVerAck func(p *Peer, msg *wire.MsgVerAck)
	// 当一个节点收到一个reject的比特币消息时启动该方法
	OnReject func(p *Peer, msg *wire.MsgReject)
	// 当一个节点收到一个sendheaders的比特币消息时启动该方法
	OnSendHeaders func(p *Peer, msg *wire.MsgSendHeaders)

	// 当一个节点收到一个比特币消息时，就会吊起这个方法。
	// 其参数由节点，读取的字节数，消息以及读取中的错误组成。
	OnRead func(p *Peer, bytesRead int, msg wire.Message, err error)

	// 当需要写入一个比特币消息到一个节点时，这个方法会被调用。
	// 其参数由节点，写入的字节数，消息以及是否发生写入错误组成。
	OnWrite func(p *Peer, bytesWritten int, msg wire.Message, err error)
}

func NewPeerBase(origCfg *Config,inbound bool)*Peer{
	// 如若不是由调用者制定，则默认为最大的支持协议版本	
	cfg := *origCfg
	if cfg.ProtocolVersion == 0 {
		cfg.ProtocolVersion = MaxProtocolVersion
	}
	if cfg.ChainParams == nil{
		cfg.ChainParams = &chaincfg.TestNet3Params
	}

	p := Peer{
		inbound:         inbound,
		wireEncoding:    wire.BaseEncoding,
		//已经发送给Peer的Inventory的缓存。
		knownInventory:  newMruInventoryMap(maxKnownInventory),
		//带缓冲的stallControlMsg chan，在收，发消息的goroutine和超时控制goroutine之间通信
		stallControl:    make(chan stallControlMsg, 1), // nonblocking sync
		//带缓冲的outMsg chan，实现了一个发送队列		
		outputQueue:     make(chan outMsg, outputBufferSize),
		//缓冲大小为1的outMsg chan，用于将outputQueue中的outMsg按加入发送队列的顺序发送给Peer。
		sendQueue:       make(chan outMsg, 1),   // nonblocking sync
		//带缓冲的channel，用于通知维护发送队列的goroutine上一个消息已经发送完成，应该取下一条消息发送。
		sendDoneQueue:   make(chan struct{}, 1), // nonblocking sync
		//实现发送inv消息的发送队列，该队列以10s为周期向Peer发送inv消息。
		outputInvChan:   make(chan *wire.InvVect, outputBufferSize),
		//用于通知收消息的goroutine已经退出
		inQuit:          make(chan struct{}),
		queueQuit:       make(chan struct{}),
		//用于通知发消息的goroutine已经退出，当收、发消息的goroutine均退出时，超时控制goroutine也将退出。
		outQuit:         make(chan struct{}),
		//用于通知所有处理事务的goroutine退出。
		quit:            make(chan struct{}),
		//与Peer相关的Config，其中比较重要是Config中的MessageListeners，
		// 指明了处理与Peer收到的消息的响应函数
		cfg:             cfg, // Copy so caller can't mutate.
		//于记录Peer支持的服务，如SFNodeNetwork表明Peer是一个全节点
		//SFNodeGetUTXO表明Peer支持getutxos和utxos命令，
		// SFNodeBloom表明Peer支持Bloom过滤
		services:        cfg.Services,
		protocolVersion: cfg.ProtocolVersion,
	    }
	    return &p

}
func (p *Peer)negotiateInboundProtocol() error{
	
	return nil
}
func (p *Peer)negotiateOutboundProtocol() error{
	if err := p.writeLocalVersionMsg();err != nil{
		return err
	}
	return p.readRemoteVersionMsg()
}
func (p *Peer)writeLocalVersionMsg() error{
	localVerMsg,err := p.localVersionMsg()
	if err != nil{
		return err
	}
	return p.writeMessage(localVerMsg,wire.LatestEncoding)
}
func (p *Peer) writeMessage(msg wire.Message, enc wire.MessageEncoding) error {
	if atomic.LoadInt32(&p.disconnect) != 0{
		return nil
	}
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Sending %v%s to %s", msg.Command(),
			summary, p)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		var buf bytes.Buffer
		_, err := wire.WriteMessageWithEncodingN(&buf, msg, p.ProtocolVersion(),
			p.cfg.ChainParams.Net, enc)
		if err != nil {
			return err.Error()
		}
		return spew.Sdump(buf.Bytes())
	}))
	n,err := wire.WriteMessageWithEncodingN(p.conn,msg,p.ProtocolVersion(), p.cfg.ChainParams.Net, enc)
	atomic.AddUint64(&p.bytesSent, uint64(n))
	if p.cfg.Listeners.OnWrite != nil {
		p.cfg.Listeners.OnWrite(p, n, msg, err)
	}
	return err
}

func (p *Peer)localVersionMsg()(*wire.MsgVersion,error){
	var blockNum int32
	if p.cfg.NewestBlock != nil{
		var err error
		_,blockNum,err := p.cfg.NewestBlock()
		if err!= nil{
			return nil,err
		}
	}
	theirNA := p.na
	if p.cfg.Proxy != "" {
		proxyaddress, _, err := net.SplitHostPort(p.cfg.Proxy)
		// invalid proxy means poorly configured, be on the safe side.
		if err != nil || p.na.IP.String() == proxyaddress {
			theirNA = wire.NewNetAddressIPPort(net.IP([]byte{0, 0, 0, 0}), 0, 0)
		}
	}
	
	ourNa := &wire.NetAddress{
		Services:p.cfg.Services,
	}
	nonce := uint64(rand.Int63())
	sentNonces.Add(nonce)
	msg := wire.NewMsgVersion(ourNa,theirNa,nonce,blockNum)
	msg.AddUserAgent(p.cfg.UserAgentName,p.cfg.UserAgentVersion,p.cfg.UserAgentComments...)
	
	msg.AddrYou.Services = wire.SFNodeNetwork
	msg.Services = p.cfg.Services
	msg.ProtocolVersion = int32(p.cfg.ProtocolVersion)
	msg.DisableRelayTx = p.cfg.DisableRelayTx
	return msg, nil
}
func (p *Peer)start() error {
	fmt.Printf("starting peer %s",p)
	negotiateErr := make (chan error)
	go func() {
		if p.inbound {
			negotiateErr <- p.negotiateInboundProtocol()
		} else {
			negotiateErr <- p.negotiateOutboundProtocol()
		}
	}()
	select {
	case err := <- negotiateErr:
		if err != nil{
			return err
		}
	case <-time.After(negotiateTimeout):
		return errors.New("protocol negotiation timeout")
	}

}





































