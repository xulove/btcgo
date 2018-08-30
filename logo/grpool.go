package logo

import "sync"

type Job func()
type worker struct {
	workerPool chan *worker
	jobChannel chan Job
	stop chan struct{}
}
func (w *worker)start(){
	go func() {
		var job Job
		for {
			w.workerPool <- w
			select {
			case job = <- w.jobChannel:
				job()
			case <- w.stop:
				w.stop<- struct{}{}
				return
			}
		}
	}()
}
func newWorker(pool chan *worker)*worker{
	return &worker{
		workerPool:pool,
		jobChannel:make(chan Job),
		stop:make(chan struct{}),
	}
}
// accepts jobs from clients
// and waits for first free worker to delever job
// dispatcher:调度er
type dispatcher struct {
	workerPool chan *worker
	jobQueue chan Job
	stop chan struct{}
}
func newDispatcher(workerPool chan *worker,jobQueue chan Job)*dispatcher{
	d := &dispatcher{
		workerPool:workerPool,
		jobQueue:jobQueue,
		stop:make(chan struct{}),
	}
	for i := 0;i<cap(d.workerPool);i++{
		worker := new
	}
}
type Pool struct {
	JobQueue chan Job
	dispatcher *dispatcher
	wg sync.WaitGroup
}
// numworkers :how many workers will be created for this pool
// queueLen :how many jobs can we accept until we block
func NewPool(numWorkers int,jobQueueLen int)*Pool{
	jobQueue := make(chan Job,jobQueueLen)
	workerPool := make(chan *worker,numWorkers)
	pool := &Pool{
		JobQueue:jobQueue
		dispatcher:newDispatcher(workerPool,jobQueue)
	}
	return pool
}

func newDispatcher(workerPool chan *worker,jobQueue chan Job)*dispatcher{
	d := &dispatcher{
		workerPool:workerPool,
		jobQueue:jobQueue,
		stop:make(chan struct{}),
	}
	for i := 0;i<cap(d.workerPool);i++{
		worker := new
	}
}














