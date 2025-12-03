package pool

import (
	"context"
	"sync"
	"time"
)

// Task 表示一个需要执行的任务
type Task func()

// GoroutinePool 表示一个goroutine池
type GoroutinePool struct {
	maxWorkers   int
	taskQueue    chan Task
	workerWaiter sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewGoroutinePool 创建一个新的goroutine池
func NewGoroutinePool(maxWorkers int, queueSize int) *GoroutinePool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &GoroutinePool{
		maxWorkers: maxWorkers,
		taskQueue:  make(chan Task, queueSize),
		ctx:        ctx,
		cancel:     cancel,
	}

	// 启动工作者goroutine
	pool.startWorkers()

	return pool
}

// startWorkers 启动工作者goroutine
func (p *GoroutinePool) startWorkers() {
	for i := 0; i < p.maxWorkers; i++ {
		p.workerWaiter.Add(1)
		go p.worker()
	}
}

// worker 工作者goroutine，负责处理任务
func (p *GoroutinePool) worker() {
	defer p.workerWaiter.Done()

	for {
		select {
		case task, ok := <-p.taskQueue:
			if !ok {
				// 任务队列已关闭，退出工作者
				return
			}
			// 执行任务
			task()
		case <-p.ctx.Done():
			// 上下文已取消，退出工作者
			return
		}
	}
}

// Submit 提交一个任务到goroutine池
func (p *GoroutinePool) Submit(task Task) error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	default:
		p.taskQueue <- task
		return nil
	}
}

// SubmitWithTimeout 提交一个任务到goroutine池，带有超时
func (p *GoroutinePool) SubmitWithTimeout(task Task, timeout time.Duration) error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case <-time.After(timeout):
		return context.DeadlineExceeded
	case p.taskQueue <- task:
		return nil
	}
}

// Close 关闭goroutine池，等待所有工作者退出
func (p *GoroutinePool) Close() {
	// 取消上下文
	p.cancel()
	// 关闭任务队列
	close(p.taskQueue)
	// 等待所有工作者退出
	p.workerWaiter.Wait()
}

// Wait 等待所有任务完成
func (p *GoroutinePool) Wait() {
	// 关闭任务队列，防止新任务提交
	close(p.taskQueue)
	// 等待所有工作者退出
	p.workerWaiter.Wait()
}
