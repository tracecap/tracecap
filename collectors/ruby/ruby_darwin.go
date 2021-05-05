// +build darwin
package ruby

import (
	"fmt"
	"log"
	"unsafe"

	"github.com/theojulienne/godtrace"
	"github.com/tracecap/tracecap/collectors"
	"github.com/tracecap/tracecap/tracecappb"
)

/*
#include <stdint.h>

typedef struct {
	uint64_t time_emit_nsec;
	uint64_t end_delta_nsec;
	uint64_t duration_nsec;
	char span_item[2048];
	char span_name[2048];
	char stacktrace[81920];
	char span_context[8192];

	int pid;
	int tid;
} trace_data_t;

typedef struct sample_data {
	int pid;
	int tid;
	uint64_t time_nsec;

	struct {
		size_t total;
		size_t free;
	} object_space;

	char stack[81920];
} sample_data_t;
*/
import "C"

type RubyMacCollector struct {
	handle *godtrace.Handle
}

func NewRubyCollector(pids []int) (*RubyMacCollector, error) {
	handle, err := godtrace.Open(0)
	if err != nil {
		return nil, err
	}

	handle.SetBufSize("24m")
	handle.SetOption("strsize", "2048")

	return &RubyMacCollector{
		handle: handle,
	}, nil
}

func (u *RubyMacCollector) Start(out chan collectors.PendingSample) error {
	prog, err := u.handle.Compile(`
	struct span_data {
		uint64_t time_emit_nsec;
		uint64_t end_delta_nsec;
		uint64_t duration_nsec;
		string span_item;
		string span_name;
		char stacktrace[81920];
		char span_context[8192];

		int pid;
		int tid;
	};

	struct ruby_span_extra {
		uint64_t ns_since_end;
	  
		uint64_t rb_stack_len;
		user_addr_t rb_stack;
	  
		uint64_t metadata_len;
		user_addr_t metadata;
	};

	:::ruby-span {
		this->extra = (struct ruby_span_extra *)alloca(sizeof(struct ruby_span_extra));
		copyinto(arg3, sizeof(struct ruby_span_extra), this->extra);

		this->span = (struct span_data *)alloca(sizeof(struct span_data));
		this->span->pid = pid;
		this->span->tid = tid;
		this->span->time_emit_nsec = walltimestamp;
		this->span->duration_nsec = arg0;
		this->span->span_item = copyinstr(arg1);
		this->span->span_name = copyinstr(arg2);
		this->span->end_delta_nsec = this->extra->ns_since_end;
		copyinto(this->extra->rb_stack, this->extra->rb_stack_len, this->span->stacktrace);
		copyinto(this->extra->metadata, this->extra->metadata_len, this->span->span_context);
		this->span->stacktrace[this->extra->rb_stack_len] = 0;
		this->span->span_context[this->extra->metadata_len] = 0;
		trace(*this->span);
	}
	
	struct sample_data {
		int pid;
		int tid;
		uint64_t time_nsec;

		struct {
			size_t total;
			size_t free;
		} object_space;

		char stack[81920];
	};

	:::ruby-sample-std {
		this->result = (struct sample_data *)alloca(sizeof(struct sample_data));
		this->result->pid = pid;
		this->result->tid = tid;
		this->result->time_nsec = walltimestamp;
		
		copyinto(arg0, sizeof(this->result->object_space), &this->result->object_space);
		copyinto(arg2, 81920, this->result->stack);
		trace(*this->result);
	}
	
	`, godtrace.ProbeSpecName, godtrace.C_PSPEC, nil)

	if err != nil {
		return err
	}
	info, err := u.handle.Exec(prog)
	if err != nil {
		return err
	}
	println("matches:", info.Matches())

	u.handle.ConsumeFunc(func(bd *godtrace.BufData) int {
		// we don't care about buffer/processed output
		// fmt.Printf("buffer data\n")
		return godtrace.ConsumeThis
	})

	u.handle.SetHandlerFunc(func(pd *godtrace.ProbeData) int {
		// desc := pd.PDesc()
		// fmt.Printf("got: %v %v:%v:%v:%v\n", pd.CPU(), desc.Provider(), desc.Mod(), desc.Func(), desc.Name())
		return godtrace.ConsumeThis
	})

	u.handle.SetRecHandlerFunc(func(pd *godtrace.ProbeData, rd *godtrace.RecDesc) int {
		if rd == nil {
			// fmt.Printf("  END\n")
			return godtrace.ConsumeNext
		}

		if rd.Action() != godtrace.ActionDIFExpression {
			// fmt.Printf("  non dif expression: %v\n", rd.Action())
			return godtrace.ConsumeNext
		}

		bytes := pd.BytesForRecord(rd)
		if len(bytes) == 0 {
			// fmt.Printf("  zero bytes\n")
			return godtrace.ConsumeNext
		}

		desc := pd.PDesc()
		// fmt.Printf("  again: %v %v:%v:%v:%v\n", pd.CPU(), desc.Provider(), desc.Mod(), desc.Func(), desc.Name())
		// fmt.Printf("  rec: %v\n", rd)
		// fmt.Printf("    bytes: %v\n", pd.BytesForRecord(rd))

		if desc.Name() == "ruby-span" {
			buf := pd.BytesForRecord(rd)
			trace_data := (*C.trace_data_t)(unsafe.Pointer(&buf[0]))
			// fmt.Printf("    trace_data_t: %v\n", trace_data)

			context := C.GoString(&trace_data.span_context[0])
			bytes := []byte(context)

			ec, metadata, err := parseContextBytes(bytes)
			if err != nil {
				log.Printf("Failed to parse context bytes: %v\n", err)
				return godtrace.ConsumeNext
			}

			var startTime uint64
			var endTime uint64
			endTime = uint64(trace_data.time_emit_nsec) - uint64(trace_data.end_delta_nsec)
			startTime = endTime - uint64(trace_data.duration_nsec)

			span_sample := &tracecappb.SpanSample{
				StartTime:     startTime,
				EndTime:       endTime,
				ComponentName: C.GoString(&trace_data.span_item[0]),
				Description:   C.GoString(&trace_data.span_name[0]),
				Id:            ec.SpanID,
				ParentId:      ec.SpanParentID,
			}

			if ec.QueueDurationNs > 0 {
				span_sample.QueueTime = uint64(ec.QueueDurationNs)
			}

			// fmt.Printf("time [%v %v]: emit=%v delta=%v duration=%v endTime=%v startTime=%v\n", span_sample.ComponentName, span_sample.Description, uint64(trace_data.time_emit_nsec), uint64(trace_data.end_delta_nsec), uint64(trace_data.duration_nsec), endTime, startTime)

			stringTrace := C.GoString(&trace_data.stacktrace[0])
			stack := parseStackTrace(stringTrace, true)

			thread_sample := &tracecappb.ThreadSample{
				Scope:          tracecappb.SampleScope_VM_RUBY,
				Purpose:        tracecappb.SamplePurpose_TRACE,
				CollectionTime: uint64(trace_data.time_emit_nsec),
				Stack:          stack,
				Span:           span_sample,
				Metadata:       metadata,
			}
			// fmt.Printf("    thread_sample: %v\n", thread_sample)
			out <- collectors.PendingSample{
				PID:    int(trace_data.pid),
				TID:    int(trace_data.tid),
				Sample: thread_sample,
			}
		} else if desc.Name() == "ruby-sample-std" {
			buf := pd.BytesForRecord(rd)
			sample_data := (*C.sample_data_t)(unsafe.Pointer(&buf[0]))
			// fmt.Printf("got sample: %v\n", C.GoString(&sample_data.stack[0]))
			// fmt.Printf("got object space: %v\n", sample_data.object_space)

			objectSpaceData := &tracecappb.ObjectSpaceSample{
				Total: uint64(sample_data.object_space.total),
				Free:  uint64(sample_data.object_space.free),
			}

			stringTrace := C.GoString(&sample_data.stack[0])
			stack := parseStackTrace(stringTrace, true)

			out <- collectors.PendingSample{
				PID: int(sample_data.pid),
				TID: int(sample_data.tid),
				Sample: &tracecappb.ThreadSample{
					Scope:          tracecappb.SampleScope_VM_RUBY,
					Purpose:        tracecappb.SamplePurpose_PROFILE,
					CollectionTime: uint64(sample_data.time_nsec),
					Stack:          stack,
					ObjectSpace:    objectSpaceData,
				},
			}

		}

		return godtrace.ConsumeNext
	})

	if err := u.handle.Go(); err != nil {
		return err
	}

	go func() {
		for {
			status, err := u.handle.Run()
			if err != nil {
				log.Fatalf("run error: %v", err)
			}
			if !status.IsOK() {
				fmt.Println("Status was not OK")
				break
			}
		}

		close(out)
	}()

	return nil
}

func (u *RubyMacCollector) Stop() error {
	return nil
}

func (u *RubyMacCollector) Close() {
	return
}

func (u *RubyMacCollector) Stats() collectors.SampleStats {
	return collectors.SampleStats{}
}
