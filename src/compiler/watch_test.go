package main

import (
	"errors"
	"reflect"
	"testing"

	esbuild "github.com/evanw/esbuild/pkg/api"
)

type watchContext struct {
	esbuild.BuildContext
	watch   func() error
	dispose func()
}

func (c *watchContext) Watch(esbuild.WatchOptions) error {
	if c.watch != nil {
		return c.watch()
	}
	return nil
}

func (c *watchContext) Dispose() {
	if c.dispose != nil {
		c.dispose()
	}
}

func TestWatchSessionConfigChangeDuringStartup(t *testing.T) {
	rebuilt := make(chan struct{})
	var events []string
	contexts := 0
	session, err := newWatchSession(func(callbacks BuildEventCallbacks) (*buildContext, error) {
		contexts++
		if contexts == 1 {
			return &buildContext{BuildContext: &watchContext{
				watch: func() error {
					callbacks.OnConfigChange()
					events = append(events, "initial watch")
					return nil
				},
				dispose: func() { events = append(events, "initial dispose") },
			}}, nil
		}
		return &buildContext{BuildContext: &watchContext{
			watch: func() error {
				events = append(events, "replacement watch")
				close(rebuilt)
				return nil
			},
			dispose: func() { events = append(events, "replacement dispose") },
		}}, nil
	}, func() { events = append(events, "delegates dispose") }, BuildEventCallbacks{})
	if err != nil {
		t.Fatal(err)
	}
	<-rebuilt
	session.Dispose()
	want := []string{"initial watch", "initial dispose", "replacement watch", "replacement dispose", "delegates dispose"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("lifecycle = %v, want %v", events, want)
	}
}

func TestWatchSessionConstructionFailure(t *testing.T) {
	wantErr := errors.New("context creation failed")
	disposals := 0
	session, err := newWatchSession(func(BuildEventCallbacks) (*buildContext, error) {
		return nil, wantErr
	}, func() { disposals++ }, BuildEventCallbacks{})
	if session != nil || !errors.Is(err, wantErr) {
		t.Fatalf("session = %v, error = %v", session, err)
	}
	if disposals != 1 {
		t.Fatalf("delegate disposals = %d, want 1", disposals)
	}
}

func TestWatchSessionRebuildAfterDispose(t *testing.T) {
	contexts := 0
	session, err := newWatchSession(func(BuildEventCallbacks) (*buildContext, error) {
		contexts++
		return &buildContext{BuildContext: &watchContext{}}, nil
	}, func() {}, BuildEventCallbacks{})
	if err != nil {
		t.Fatal(err)
	}
	session.Dispose()
	session.rebuild()
	if contexts != 1 {
		t.Fatalf("contexts = %d, want 1", contexts)
	}
}
