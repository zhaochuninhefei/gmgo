/*
 *
 * Copyright 2022 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package grpcsync

import (
	"context"

	"gitee.com/zhaochuninhefei/gmgo/grpc/internal/buffer"
)

// CallbackSerializer provides a mechanism to schedule callbacks in a
// synchronized manner. It provides a FIFO guarantee on the order of execution
// of scheduled callbacks. New callbacks can be scheduled by invoking the
// Schedule() method.
//
// This type is safe for concurrent access.
type CallbackSerializer struct {
	// done is closed once the serializer is shut down completely, i.e all
	// scheduled callbacks are executed and the serializer has deallocated all
	// its resources.
	done chan struct{}

	callbacks *buffer.Unbounded
}

// NewCallbackSerializer returns a new CallbackSerializer instance. The provided
// context will be passed to the scheduled callbacks. Users should cancel the
// provided context to shutdown the CallbackSerializer. It is guaranteed that no
// callbacks will be added once this context is canceled, and any pending un-run
// callbacks will be executed before the serializer is shut down.
func NewCallbackSerializer(ctx context.Context) *CallbackSerializer {
	cs := &CallbackSerializer{
		done:      make(chan struct{}),
		callbacks: buffer.NewUnbounded(),
	}
	go cs.run(ctx)
	return cs
}

// Schedule adds a callback to be scheduled after existing callbacks are run.
//
// Callbacks are expected to honor the context when performing any blocking
// operations, and should return early when the context is canceled.
//
// Return value indicates if the callback was successfully added to the list of
// callbacks to be executed by the serializer. It is not possible to add
// callbacks once the context passed to NewCallbackSerializer is cancelled.
func (cs *CallbackSerializer) Schedule(f func(ctx context.Context)) bool {
	return cs.callbacks.Put(f) == nil
}

func (cs *CallbackSerializer) run(ctx context.Context) {
	defer close(cs.done)

	// TODO: when Go 1.21 is the oldest supported version, this loop and Close
	// can be replaced with:
	//
	// context.AfterFunc(ctx, cs.callbacks.Close)
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			// Do nothing here. Next iteration of the for loop will not happen,
			// since ctx.Err() would be non-nil.
		case cb := <-cs.callbacks.Get():
			cs.callbacks.Load()
			cb.(func(context.Context))(ctx)
		}
	}

	// Close the buffer to prevent new callbacks from being added.
	cs.callbacks.Close()

	// Run all pending callbacks.
	for cb := range cs.callbacks.Get() {
		cs.callbacks.Load()
		cb.(func(context.Context))(ctx)
	}
}

// Done returns a channel that is closed after the context passed to
// NewCallbackSerializer is canceled and all callbacks have been executed.
func (cs *CallbackSerializer) Done() <-chan struct{} {
	return cs.done
}
