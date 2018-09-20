package addrmgr

type AddrManager struct{
	// AddrManager的对象锁，保证addrManager是并发安全的
	mtx sync.Mutex
	// peersFile:存储地址仓库的文件名，默认为peers.json
	peersFile string
	// 进行DNS Lookup的函数值
	lookupFunc func(string)([]net.IP,error)
	// 随机数生成器
	rand *rand.Rand
	// 32字节的随机数数序列，用与计算NewBucket和TriedBucket的索引
	key [32]byte
	// addIndex 缓存所有的KnownAddress的map
	addrIndex map[string]*KnownAddress
	// 缓存所有新地址的map slice
	addrNew        [newBucketCount]map[string]*KnownAddress
	// 缓存所有已经Tried的地址的list slice。
	//请注意与addrNew用到map不同，这里用到了list，然而从AddrManager的实现上看，addrNew和addrTired分别用map和list的差别并不大，一个可能是原因是在GetAddress()中从NewBucket或才TriedBucket选择地址时，list可能按顺序访问，而map通过range遍历元素的顺序是随机的;
	addTried [triedBucketCount]*list.List
	// 用于标识addrmanager已经启动
	started int32
	// 用于标识addrmanager已经停止
	shutdown int32
	// 用于同步退出，addrmanager停止时等待工作协成退出
	wg sync.WaitGroup
	// 用于通知工作协成退出
	quit chan struct{}
	// 记录Tried地址个数
	nTried int
	// 记录New 地址个数
	nNew int
	// 保护localAddresses的互斥锁
	lamtx sync.Mutex
	// 保存一直的本地地址
	localAddresses map[string]*localAddress
}

// serializedAddrManager结构体中的字段，分别对应地址仓库peers.json中的信息
type serializedAddrManager struct{
	Version int
	Key [32]byte
	Addresses []*serializedKnownAddress
	NewBuckets [newBucketCount][]string
	TriedBuckets [triedBucketCount][]string
}
// serializedKnownAddress对应peers.json中addresses字段记录的地址集
type serializedKnownAddress struct{
	Addr string
	Src string
	Attempts int
	TimeStamp int64
	LastAttempt int64
	LastSuccess int64
}

// serializedKnownAddress对应的实例化类型是knownAddress
type　KnownAddress struct{
	// na:从addr消息获知的的节点的IPv4 or IPv6地址
	// peers.json中有“.onion”的地址，是由特定的支持Tor的IPv6地址转化而来的
	na *wire.NetAddress
	// addr消息的源，也是当前节点的peer
	srcAddr *wire.NetAddress
	// 连接成功之前尝试连接的次数
	attempts int
	// 最近一次尝试连接的时间点
	lastattempt time.Time
	// 最近一次连城成功的时间点
	lastsuccess time.Time
	// 标识是否已经尝试连接过，已经treid过的地址将被放到TriedBuckets
	tried bool
	// 该地址所属的NewBucket的个数，默认最大个数是8
	refs int
}
func (a *AddrManager) Start(){
	if atomic.AddInt32(&a.started,1) != 1{
		return
	}
	log.Trace("starting address manager")
	a.loadPeers()
	a.wg.Add(1)
	go a.addressHandler()
}

func (a *AddrManager)loadPeers(){
	a.mtx.Lock()
	defer a.mtx.Unlock()
	
	err := a.deserializePeers(a.peersFile)
	if err != nil {
		log.Errorf("Failed to parse file %s: %v", a.peersFile, err)
		// if it is invalid we nuke the old one unconditionally.
		err = os.Remove(a.peersFile)
		if err != nil {
			log.Warnf("Failed to remove corrupt peers file %s: %v",
				a.peersFile, err)
		}
		a.reset()
		return
	}
	log.Infof("Loaded %d addresses from file '%s'", a.numAddresses(), a.peersFile)
}
func (a  *AddrManager)deserializePeers(filePath string)error{
	_,err := os.Stat(filepath)
	if os.IsNotExist(filePath){
		return nil
	}
	//// 读取文件，并通过json解析器将json文件实例化为serializedAddrManager对象
	r,err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("%s error opening file: %v", filePath, err)
	}
	defer r.Close()
	
	var sam serializedAddrManager
	//func NewDecoder(r io.Reader) *Decoder
	// NewDecoder创建一个从r读取并解码json对象的*Decoder，解码器有自己的缓冲，并可能超前读取部分json数据。
	dec := json.NewDecoder(r)
	err := dec.Decode(&sam)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filePath, err)
	}
	//校验版本号，并读取随机数序列Key;
	if sam.Version != serialisationVersion{
		 return fmt.Errorf("unknown version %v in serialized "+
            "addrmanager", sam.Version)
	}
	
	copy (a.key[:],sam.key[:])
	//将serializedKnownAddress解析为KnownAddress，并存入a.addrIndex中。需要注意的是，serializedKnownAddress中的地址均是string，而KnownAddress对应的地址是wire.NetAddress类型，在转换过程中，如果serializedKnownAddress为“.onion”的洋葱地址，则将“.onion”前的字符串转换成大写后进行base32解码，并添加“fd87:d87e:eb43”前缀转换成IPv6地址；如果是hostname，则调用lookupFunc将将解析为IP地址；同时，addrIndex的key是地址的string形式，如果是IP:Port的形式，则直接将IP和Port转换为对应的数字字符，如果是以“fd87:d87e:eb43”开头的IPv6地址，则将该地址的后10位进行base32编码并转成小写后的字符串，加上“.onion”后缀转换为洋葱地址形式。具体转换过程在ipString()和HostToNetAddress()中实现;

	for _,v := range sam.Address{
		ka:= new(KnownAddress)
		ka.na ,err := a.DeserializeNetAddress(v.Addr)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Addr, err)
		}
		ka.srcAddr,err := a.DeserializeNetAddress(v.Src)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Src, err)
		}
		ka.attempts = v.Attempts
		ka.lastattempt = time.Unix(v.LastAttempt,0)
		ka.lastsuccess = time.Unix(v.LastSuccess,0)
		a.addrIndex[NetAddressKey(ka.na)]= ka
	}
	//以serializedAddrManager的NewBuckets和TriedBuckets中的地址为Key，查找addrIndex中对应的KnownAddress后，填充addrNew和addrTried;
	for i := range sam.NewBuckets{
		for _,val := range sam.NewBuckets[i]{
			ka,ok :=a.addrIndex[val]
			if !ok {
				return fmt.Errorf("newbucket contains %s but "+
					"none in address list", val) 
			}
			if ka.refs == 0 {
				a.nNew++
			}
			ka.refs++
			a.addIndex[i][val] = ka
		}
	}
	// 最后对实例化的结果作Sanity检查，保证一个地址要么在NewBuckets中，要么在TridBuckets中;
	for i := range sam.TriedBuckets{
		for _,val := range sam.TriedBuckets[i]{
			ka,ok := a.addrIndex[val]
			if !ok {
				return fmt.Errorf("Newbucket contains %s but "+
					"none in address list", val)
			}
			ka.tried = true
			a.nTried++
			a.addrTried[i]PushBack(ka)
		}
	}
	for k,v := range a.addrIndex{
		if v.refs == 0&& !v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"with no references", k)
		}
		if v.refs > 0 &&  v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"which is both new and tried!", k)
		}
	}
	return nil
}

func (a *AddrManager) DeserializeNetAddress(addr string) (*wire.NetAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	return a.HostToNetAddress(host, uint16(port), wire.SFNodeNetwork)
}
// 它的主要执行过程就是每隔dumpAddressInterval(值为10分钟)调用savePeers()将addrMananager中的地址集写入文件，savePeers()是与deserializePeers()对应的实例化方法，我们不再分析它的实现
func (a *AddrManager) addressHandler(){
	dumpAddressTicker := time.NewTicker(dumpAddressInterval)
	defer dumpAddressTicker.Stop()
	
	out:
	for {
		select {
			case <- dumpAddressTicker.C:
				a.savePeers()
			case <- a.quit:
				break out
		}
	}
	a.savePeers()
	a.wg.Done()
	log.Trace("Address handler done")
}

func (a *AddrManager) savePeers(){
	a.mtx.Lock()
	defer a.mtx.Unlock()
	
	sam:= new(serializedAddrManager)
	sam.Version = serialisationVersion
	copy(sam.Key[:],a.key[:])
	
	sam.Addresses = make([]*serializedKnownAddress,len(a.addrIndex))
	i := 0
	for k,v := range a.ddrIndex{
		ska := new(serializedKnownAddress)
		ska.Addr = k
		ska.TimeStamp = v.na.Timestamp.Unix()
		ska.Src = NetAddressKey(v.srcAddr)
		ska.Attempts = v.attempts
		ska.LastSuccess = v.lastsuccess.Unix()
		sam.Addresses[i] = ska
		i++
	}
	
	for i := range a.addrNew {
		sam.NewBuckets[i] = make([]string,len(a.addrNew[i]))
		j := 0
		for k := range a.addrNew[i] {
			sam.NewBuckets[i][j] = k
			j++
		}
	}
	for i := range a.addrTried {
		sam.TriedBuckets[i] = make([]string, a.addrTried[i].Len())
		j := 0
		for e := a.addrTried[i].Front(); e != nil; e = e.Next() {
			ka := e.Value.(*KnownAddress)
			sam.TriedBuckets[i][j] = NetAddressKey(ka.na)
			j++
		}
	}
	w, err := os.Create(a.peersFile)
	if err != nil {
		log.Errorf("Error opening file %s: %v", a.peersFile, err)
		return
	}
	enc := json.NewEncoder(w)
	defer w.Close()
	if err := enc.Encode(&sam); err != nil {
		log.Errorf("Failed to encode file %s: %v", a.peersFile, err)
		return
	}
	
}

func (a *AddrManager) updateAddress(netAddr,srcAddr *wire.NetAddress){
	//判断欲添加的地址netAddr是否是可路由的地址，即除了保留地址以外的地址，如果是不可以路由的地址，则不加入地址仓库;
	if !IsToutable(netAddr) {
		return 
	}
	addr := NetaddressKey(netAddr)
	ka := a.find(netAddr)
	if ka != nil {
		//查询欲添加的地址是否已经在地址集中，如果已经在，且它的时间戳更新或者有支持新的服务，则更新地址集中KnownAddress，如代码(2)所示。请注意，这里的时间戳是指节点最近获知该地址的时间点;
		if netAddr.Timestamp.After(ka.na.Timestamp) ||
		(ka.na.Services&netAddr.Services) != netAddr.Services {
			naCopy := *ka.na
			naCopy.Timestamo = netAddr.Timestamp
			naCopy.AddService(netAddr.Services)
			ka.na = &naCopy
		}
		// 检查如果地址已经在TriedBucket中，则不更新地址仓库
		if ka.tried {
			return 
		}
		// 检查如果地址已经位于8个不同的NewBucket中，也不更新仓库
		if ka.refs == newBucketsPerAddress{
			return
		}
		// 根据地址已经被NewBucket引用的个数，来随机决定是否继续添加到NewBucket中
		factor := int32(2 * ka.refs)
		if a.rand.Int32n(factor) != 0 {
			return 
		}
	} else {
		netAddrCopy := *netAddr                                                   (6)
        ka = &KnownAddress{na: &netAddrCopy, srcAddr: srcAddr}
        a.addrIndex[addr] = ka
        a.nNew++
	}
	bucket := a.getNewBucket(netAddr, srcAddr)                                    (7)

    // Already exists?
    if _, ok := a.addrNew[bucket][addr]; ok {
        return
    }

    // Enforce max addresses.
    if len(a.addrNew[bucket]) > newBucketSize {
        log.Tracef("new bucket is full, expiring old")
        a.expireNew(bucket)                                                       (8)
    }

    // Add to new bucket.
    ka.refs++
    a.addrNew[bucket][addr] = ka                                                  (9)

    log.Tracef("Added new address %s for a total of %d addresses", addr,
        a.nTried+a.nNew)
}








