package peer

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcgo/logo"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"github.com/davecgh/go-spew/spew"
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

func NewPeerBase(origCfg *Config, inbound bool) *Peer {
	// 如若不是由调用者制定，则默认为最大的支持协议版本
	cfg := *origCfg
	if cfg.ProtocolVersion == 0 {
		cfg.ProtocolVersion = MaxProtocolVersion
	}
	if cfg.ChainParams == nil {
		cfg.ChainParams = &chaincfg.TestNet3Params
	}

	p := Peer{
		inbound:      inbound,
		wireEncoding: wire.BaseEncoding,
		//已经发送给Peer的Inventory的缓存。
		knownInventory: newMruInventoryMap(maxKnownInventory),
		//带缓冲的stallControlMsg chan，在收，发消息的goroutine和超时控制goroutine之间通信
		stallControl: make(chan stallControlMsg, 1), // nonblocking sync
		//带缓冲的outMsg chan，实现了一个发送队列
		outputQueue: make(chan outMsg, outputBufferSize),
		//缓冲大小为1的outMsg chan，用于将outputQueue中的outMsg按加入发送队列的顺序发送给Peer。
		sendQueue: make(chan outMsg, 1), // nonblocking sync
		//带缓冲的channel，用于通知维护发送队列的goroutine上一个消息已经发送完成，应该取下一条消息发送。
		sendDoneQueue: make(chan struct{}, 1), // nonblocking sync
		//实现发送inv消息的发送队列，该队列以10s为周期向Peer发送inv消息。
		outputInvChan: make(chan *wire.InvVect, outputBufferSize),
		//用于通知收消息的goroutine已经退出
		inQuit:    make(chan struct{}),
		queueQuit: make(chan struct{}),
		//用于通知发消息的goroutine已经退出，当收、发消息的goroutine均退出时，超时控制goroutine也将退出。
		outQuit: make(chan struct{}),
		//用于通知所有处理事务的goroutine退出。
		quit: make(chan struct{}),
		//与Peer相关的Config，其中比较重要是Config中的MessageListeners，
		// 指明了处理与Peer收到的消息的响应函数
		cfg: cfg, // Copy so caller can't mutate.
		//于记录Peer支持的服务，如SFNodeNetwork表明Peer是一个全节点
		//SFNodeGetUTXO表明Peer支持getutxos和utxos命令，
		// SFNodeBloom表明Peer支持Bloom过滤
		services:        cfg.Services,
		protocolVersion: cfg.ProtocolVersion,
	}
	return &p

}

//等待并读取、处理Peer发过来的Version消息;
// 向Peer发送自己的Version消息;
func (p *Peer) negotiateInboundProtocol() error {
	if err := p.readRemoteVersionMsg(); err != nil {
		return err
	}

	return p.writeLocalVersionMsg()
}
func (p *Peer) negotiateOutboundProtocol() error {
	if err := p.writeLocalVersionMsg(); err != nil {
		return err
	}
	return p.readRemoteVersionMsg()
}
func (p *Peer) writeLocalVersionMsg() error {
	localVerMsg, err := p.localVersionMsg()
	if err != nil {
		return err
	}
	return p.writeMessage(localVerMsg, wire.LatestEncoding)
}
func (p *Peer) writeMessage(msg wire.Message, enc wire.MessageEncoding) error {
	if atomic.LoadInt32(&p.disconnect) != 0 {
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
	n, err := wire.WriteMessageWithEncodingN(p.conn, msg, p.ProtocolVersion(), p.cfg.ChainParams.Net, enc)
	atomic.AddUint64(&p.bytesSent, uint64(n))
	if p.cfg.Listeners.OnWrite != nil {
		p.cfg.Listeners.OnWrite(p, n, msg, err)
	}
	return err
}

func (p *Peer) localVersionMsg() (*wire.MsgVersion, error) {
	var blockNum int32
	if p.cfg.NewestBlock != nil {
		var err error
		_, blockNum, err := p.cfg.NewestBlock()
		if err != nil {
			return nil, err
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
		Services: p.cfg.Services,
	}
	nonce := uint64(rand.Int63())
	sentNonces.Add(nonce)
	msg := wire.NewMsgVersion(ourNa, theirNa, nonce, blockNum)
	msg.AddUserAgent(p.cfg.UserAgentName, p.cfg.UserAgentVersion, p.cfg.UserAgentComments...)

	msg.AddrYou.Services = wire.SFNodeNetwork
	msg.Services = p.cfg.Services
	msg.ProtocolVersion = int32(p.cfg.ProtocolVersion)
	msg.DisableRelayTx = p.cfg.DisableRelayTx
	return msg, nil
}
func (p *Peer) start() error {
	fmt.Printf("starting peer %s", p)
	negotiateErr := make(chan error)
	go func() {
		if p.inbound {
			negotiateErr <- p.negotiateInboundProtocol()
		} else {
			negotiateErr <- p.negotiateOutboundProtocol()
		}
	}()
	select {
	case err := <-negotiateErr:
		if err != nil {
			return err
		}
	case <-time.After(negotiateTimeout):
		return errors.New("protocol negotiation timeout")
	}
	log.Debugf("Connected to %s", p.Addr())
	go p.stallHandler()
	go p.inHandler()
	go p.queueHandler()
	go p.outHandler()
	go p.pingHandler()
	
	p.QueueMessage(wire.NewMsgVerAck(),nil)
	return nil
}

func (p *Peer) handleRemoteVersionMsg(msg *wire.MsgVersion) error {
	//检测Version消息里的Nonce是否是自己缓存的nonce值，如果是，则表明该Version消息由自己发送给自己，在实际网络下，不允许节点自己与自己结成Peer，所以这时会返回错误;
	if !allowSelfConns && sentNonces.Exists(msg.Nonce) {
		return errors.New("disconnecting peer connected to self")
	}
	//检测Version消息里的ProtocolVersion，如果Peer的版本低于209，则拒绝与之相连
	if msg.ProtocalVersion < int32(wire.MutipleAddressVersion) {
		reason := fmt.Sprintf("protocol version must be %d or greater", wire.MutipleAddressVersion)
		rejectMsg := wire.NewMsgReject(msg.Commad(), wire.RejectObsolete, reason)
		return p.writeMessage(rejectMsg)
	}
	//Nonce和ProtocolVersion检查通过后，就开始更新Peer的相关信息，如Peer的最新区块高度、Peer与本地节点的时间偏移等;
	p.statsMtx.Lock()
	p.lastBlock = msg.LastBlock
	p.startingHeight = msg.LastBlcok
	p.timeOffset = msg.Timestamp.Unix() - time.Now().Unix()
	p.statsMtx.Unlock()
	
	p.flagMtx.Lock()
	p.advertiseProtoVer = uint32(msg.ProtocolVersion)
	p.protocolVersion = minUint32(p.protocolVersion,p.advertiseProtoVer)
	p.versionKnown = true
	log.Debugf("Negotiated protocol version %d for peer %s",
		p.protocolVersion, p)
	
	//set the peer's ID
	p.id = atomic.AddInt32(&nodeCount,1)
	p.services = msg.Services
	
	// set the remote peer's user agent
	p.userAgent = msg.UserAgent
	
	if p.services & wire.SFNodeWitness== wire.SFNodeWitness {
		p.witnessEnable = true
	}
	p.flagMtx.Unlock()
	if p.services&wire.SFNodeWitness = wire.SFNodeWitness {
		p.wireEncoding = wire.WitnessEncoding
	}
	return nil
}
/*
inHandler协程主要处理接收消息，并回调MessageListener中的消息处理函数对消息进行处理，需要注意的是，回调函数处理消息时不能太耗时，否则会收引起超时断连
*/
func (p *peer) inHandler() {
	//设定一个idleTimer，其超时时间为5分钟。如果每隔5分钟内没有从Peer接收到消息，则主动与该Peer断开连接。我们在后面分析pingHandler时将会看到，往Peer发送ping消息的周期是2分钟，也就是说最多约2分钟多一点(2min + RTT + Peer处理Ping的时间，其中RTT一般为ms级)需要收到Peer回复的Pong消息，所以如果5min没有收到回复，可以认为Peer已经失去联系
	idleTimer := time.AfterFunc(idleTimeout,func(){
		log.Warnf("Peer %s no answer for %s -- disconnecting",p,idleTimeout)
		p.Disconnect()
	})
	//循环读取和处理从Peer发过来的消息。当5min内收到消息时，idleTimer暂时停止。请注意，消息读取完毕后，inHandler向stallHandler通过stallControl channel发送了sccReceiveMessage消息，并随后发送了sccHandlerStart，stallHandler会根据这些消息来计算节点接收并处理消息所消耗的时间，我们在后面分析stallHandler分详细介绍。
out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		rmsg,buf,err := p.readMessage(p.wireEncoding)
		idleTimer.Stop()
		if err != nil {
			if p.isAllowedReadError(err) {
				log.Debugf("Connected to %s", p.Addr())
				idleTimer.Reset(idleTimeout)
				continue
			}
			
			if p.shouldHandleReadError(err) {
				errMsg := fmt.Sprintf("Can't read message from %s: %v", p, err)
				if err != io.ErrUnexpectedEOF {
					log.Errorf(errMsg)
				}

				// Push a reject message for the malformed message and wait for
				// the message to be sent before disconnecting.
				//
				// NOTE: Ideally this would include the command in the header if
				// at least that much of the message was valid, but that is not
				// currently exposed by wire, so just used malformed for the
				// command.
				p.PushRejectMsg("malformed", wire.RejectMalformed, errMsg, nil,
					true)
			}
			break out
		}
		atomic.StoreInt64(&p.lastRecv, time.Now().Unix())
		p.stallControl <- stallControlMsg{sccHandlerStart,rmsg}
		//在处理Peer发送过来的消息时，inHandler可能先对其作处理，如MsgPing和MsgPong，也可能不对其作任何处理，如MsgBlock等等，然后回调MessageListener的对应函数作处理。
		swicht msg:= rmsg.(type){
		case *wire.MsgVersion:
			p.PushRejectMsg(msg.Command(), wire.RejectDuplicate,
				"duplicate version message", nil, true)
			break out
		case *wire.MsgVerAck:

			// No read lock is necessary because verAckReceived is not written
			// to in any other goroutine.
			if p.verAckReceived {
				log.Infof("Already received 'verack' from peer %v -- "+
					"disconnecting", p)
				break out
			}
			p.flagsMtx.Lock()
			p.verAckReceived = true
			p.flagsMtx.Unlock()
			if p.cfg.Listeners.OnVerAck != nil {
				p.cfg.Listeners.OnVerAck(p, msg)
			}

		case *wire.MsgGetAddr:
			if p.cfg.Listeners.OnGetAddr != nil {
				p.cfg.Listeners.OnGetAddr(p, msg)
			}

		case *wire.MsgAddr:
			if p.cfg.Listeners.OnAddr != nil {
				p.cfg.Listeners.OnAddr(p, msg)
			}

		case *wire.MsgPing:
			p.handlePingMsg(msg)
			if p.cfg.Listeners.OnPing != nil {
				p.cfg.Listeners.OnPing(p, msg)
			}

		case *wire.MsgPong:
			p.handlePongMsg(msg)
			if p.cfg.Listeners.OnPong != nil {
				p.cfg.Listeners.OnPong(p, msg)
			}

		case *wire.MsgAlert:
			if p.cfg.Listeners.OnAlert != nil {
				p.cfg.Listeners.OnAlert(p, msg)
			}

		case *wire.MsgMemPool:
			if p.cfg.Listeners.OnMemPool != nil {
				p.cfg.Listeners.OnMemPool(p, msg)
			}

		case *wire.MsgTx:
			if p.cfg.Listeners.OnTx != nil {
				p.cfg.Listeners.OnTx(p, msg)
			}

		case *wire.MsgBlock:
			if p.cfg.Listeners.OnBlock != nil {
				p.cfg.Listeners.OnBlock(p, msg, buf)
			}

		case *wire.MsgInv:
			if p.cfg.Listeners.OnInv != nil {
				p.cfg.Listeners.OnInv(p, msg)
			}

		case *wire.MsgHeaders:
			if p.cfg.Listeners.OnHeaders != nil {
				p.cfg.Listeners.OnHeaders(p, msg)
			}

		case *wire.MsgNotFound:
			if p.cfg.Listeners.OnNotFound != nil {
				p.cfg.Listeners.OnNotFound(p, msg)
			}

		case *wire.MsgGetData:
			if p.cfg.Listeners.OnGetData != nil {
				p.cfg.Listeners.OnGetData(p, msg)
			}

		case *wire.MsgGetBlocks:
			if p.cfg.Listeners.OnGetBlocks != nil {
				p.cfg.Listeners.OnGetBlocks(p, msg)
			}

		case *wire.MsgGetHeaders:
			if p.cfg.Listeners.OnGetHeaders != nil {
				p.cfg.Listeners.OnGetHeaders(p, msg)
			}

		case *wire.MsgGetCFilters:
			if p.cfg.Listeners.OnGetCFilters != nil {
				p.cfg.Listeners.OnGetCFilters(p, msg)
			}

		case *wire.MsgGetCFHeaders:
			if p.cfg.Listeners.OnGetCFHeaders != nil {
				p.cfg.Listeners.OnGetCFHeaders(p, msg)
			}

		case *wire.MsgGetCFCheckpt:
			if p.cfg.Listeners.OnGetCFCheckpt != nil {
				p.cfg.Listeners.OnGetCFCheckpt(p, msg)
			}

		case *wire.MsgCFilter:
			if p.cfg.Listeners.OnCFilter != nil {
				p.cfg.Listeners.OnCFilter(p, msg)
			}

		case *wire.MsgCFHeaders:
			if p.cfg.Listeners.OnCFHeaders != nil {
				p.cfg.Listeners.OnCFHeaders(p, msg)
			}

		case *wire.MsgFeeFilter:
			if p.cfg.Listeners.OnFeeFilter != nil {
				p.cfg.Listeners.OnFeeFilter(p, msg)
			}

		case *wire.MsgFilterAdd:
			if p.cfg.Listeners.OnFilterAdd != nil {
				p.cfg.Listeners.OnFilterAdd(p, msg)
			}

		case *wire.MsgFilterClear:
			if p.cfg.Listeners.OnFilterClear != nil {
				p.cfg.Listeners.OnFilterClear(p, msg)
			}

		case *wire.MsgFilterLoad:
			if p.cfg.Listeners.OnFilterLoad != nil {
				p.cfg.Listeners.OnFilterLoad(p, msg)
			}

		case *wire.MsgMerkleBlock:
			if p.cfg.Listeners.OnMerkleBlock != nil {
				p.cfg.Listeners.OnMerkleBlock(p, msg)
			}

		case *wire.MsgReject:
			if p.cfg.Listeners.OnReject != nil {
				p.cfg.Listeners.OnReject(p, msg)
			}

		case *wire.MsgSendHeaders:
			p.flagsMtx.Lock()
			p.sendHeadersPreferred = true
			p.flagsMtx.Unlock()

			if p.cfg.Listeners.OnSendHeaders != nil {
				p.cfg.Listeners.OnSendHeaders(p, msg)
			}

		default:
			log.Debugf("Received unhandled message of type %v "+
				"from %v", rmsg.Command(), p)
		}
		//在处理完一条消息后，inHandler向stallHandler发送sccHandlerDone，通知stallHandler消息处理完毕。同时，将idleTimer复位再次开始计时，并等待读取下一条消息;
		p.stallControl <- stallControlMsg{sccHandlerDone, rmsg}
		idleTimer.Reset(idleTimeout)
	}
	//当主动调用Disconnect()与Peer断开连接后，消息读取和处理循环将退出，inHandler协和也准备退出。退出之前，先将idleTimer停止，并再次主动调用Disconnect()强制与Peer断开连接，最后通过inQuit channel向stallHandler通知自己已经退出
	idleTimer.Stop()
	p.Disconnect()
	close(p.inQuit)
	log.Tracef("Peer input handler done for %s", p)
	
}

func (p *Peer) outHandler() {
	out:
	for{
		select {
		case msg:= <- p.sendQueue:
			switch m := msg.msg.(type){
			case *wire.MsgPing:
				if p.ProtocolVersion() > wire.BIP0031Version{
					p.statsMtx.Lock()
					p.lashPingNonce = m.Nonce
					p.lastPingTime = time.Now()
					p.statsMtx = Unlock()
				}
			}
			p.stallControl <- stallControlMsg{sccSendMessage,msg,msg}
			err := p.writeMessage(msg.msg,msg.encoding)
			if err != nil {
				p.Disconnect()
				if p.shouldLogWriteError(err){
					log.Errorf("Failed to send message to "+
						"%s: %v", p, err)
				}
				if msg.doneChan != nil {
					msg.doneChan <- struct {}{}
				}
				continue
			}
			atomic.StoreInt64(&p.lastSend,time.Now().Unix())
			if msg.doneChan != nil {
				msg.doneChan <- struct {}{}
			}			
			p.sendDoneQueue <- struct {}{}
		case <- p.quit:
			break out
		}
	}
}





























