## btcdMain()
- loadConfig()
- interrupt - ctrl+c
- loadDB()
- newServe()
    - amgr:addrmgr.new()
    - listeners:initListeners()
    - server.chain:blockchain.new()
    - server.txMemPool:mempool.new()
    - server.syncManager:netsync.new()
    - server.cpuMinder:cpuminer.new()
    - server.connManager:connmgr.new()
    - server.rpcServer:newRPCServer()
- server.start()
    - go s.peerHandler()
        - s.addrManager.Start() 
            - loadPeers（） //从文件中加载节点列表
            - go a.addressHandler() // 定时保存地址列表到peer.json文件
        - s.syncManager.Start()
            - blockHandler()  //从 <-sm.msgChan通道读取消息，然后分发处理 
        - go s.connManager.Start()
            - go cm.connHanler() //从cm.request通道获得不同类型的信息
            - go cm.listenHandler(listner)
            - go cm.cfg.OnAccept(conn)
            
        - for循环读取消息
            
        
    - go s.upnpUpdateThread()
    - go s.rebroadcastHandler()
    - s.rpcServer.Start()
    - go s.cpuMiner.start()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    