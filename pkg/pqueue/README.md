# pqueue
A simple thread safe priority queue implementation

## Usage

Create a new queue, specifying how many priority values you want to support
```go
q := pqueue.New(8)
```

Insert some data, specifying the priority
```go
q.Push(4, "some priority 4 data")
```

Pop a message from the queue
```go
v := q.Pop()
```

Popping is a blocking operation. If the queue is empty, pop will block until a new item has been pushed


## Tests

```sh
$ go test -v -race 
```
