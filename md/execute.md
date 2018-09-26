## peer包
	peer.go 
	> 首先我们调用`NewPeerBase`生成一个peer对象，然后调用`peer`对象的`start()`方法。`start`方法中，会给`p.conn`发送一个`*wire.MsgVersion` 数据。（？？ p.conn是如何来的还不知？？）
	发送的同时，也会调用`p.readRemoteVersionMsg()`方法，来读取返会的version信息。
	读取返会的version信息后，先是调用`p.handleRemoteVersionMsg(remoteVerMsg)`来处理信息，主要就是按照返会的信息，来更新自己的信息。然后回调`MessageListeners中的OnVersion`进一步处理。`MessageListeners`是包含在config结构体中的，config是在`newPeerBase()`的时候传入的。
	


