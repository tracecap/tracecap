// +build linux
package ruby

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/tracecap/tracecap/collectors"
	"github.com/tracecap/tracecap/tracecappb"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	ringbuffer "github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

// #cgo CFLAGS: -I/usr/include/bcc
// #cgo LDFLAGS: -lbcc
// #include <libbpf.h>
// #include <bcc/bcc_usdt.h>
/*
#include <linux/ptrace.h>
#include <string.h>

#define HANDLE_ARG_REG(reg_name, field) if (!strcmp(arg->base_register_name, reg_name)) { return offsetof(struct pt_regs, field); }

static int _offset_for_usdt_arg(struct bcc_usdt_argument *arg) {
	HANDLE_ARG_REG("r15", r15)
	HANDLE_ARG_REG("r14", r14)
	HANDLE_ARG_REG("r13", r13)
	HANDLE_ARG_REG("r12", r12)
	HANDLE_ARG_REG("bp", rbp)
	HANDLE_ARG_REG("bx", rbx)
	HANDLE_ARG_REG("r11", r11)
	HANDLE_ARG_REG("r10", r10)
	HANDLE_ARG_REG("r9", r9)
	HANDLE_ARG_REG("r8", r8)
	HANDLE_ARG_REG("ax", rax)
	HANDLE_ARG_REG("cx", rcx)
	HANDLE_ARG_REG("dx", rdx)
	HANDLE_ARG_REG("si", rsi)
	HANDLE_ARG_REG("di", rdi)
	HANDLE_ARG_REG("ip", rip)
	HANDLE_ARG_REG("cs", cs)
	HANDLE_ARG_REG("sp", rsp)
	HANDLE_ARG_REG("ss", ss)
	return 0;
}
*/
import "C"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "linux" -cc clang-9 rubyEbpfReader bpf/ruby_reader.c

const STACK_LEN = 48 << 10

type spanEvent struct {
	Pid uint64
	Tid uint64

	TimeEmitNsec uint64
	EndDeltaNsec uint64
	DurationNsec uint64
	SpanItem     [64]byte
	SpanName     [64]byte

	SpanContext [8192]byte

	RubyStack [STACK_LEN]byte
}

type profileEvent struct {
	Pid uint64
	Tid uint64

	TimeEmitNsec uint64

	ObjectSpaceFree  uint64
	ObjectSpaceTotal uint64

	RubyStack [STACK_LEN]byte
}

type collectorProbe struct {
	pid    int
	usdt   unsafe.Pointer
	evName string
}

type RubyLinuxCollector struct {
	probes     []*collectorProbe
	spanReader *ringbuffer.Reader
	dropped    uint64
}

func setupEbpf() error {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		return fmt.Errorf("failed to set rlimit for eBPF: %v", err)
	}

	return nil
}

func NewRubyCollector(pids []int) (*RubyLinuxCollector, error) {
	probes := []*collectorProbe{}

	for _, pid := range pids {
		probe := &collectorProbe{
			pid: pid,
		}

		probe.usdt = C.bcc_usdt_new_frompid(C.int(pid), nil)
		if probe.usdt == nil {
			return nil, fmt.Errorf("Expected bcc_usdt_new_frompid to find process %v", pid)
		}
		fmt.Printf("New probe for pid %d %v\n", pid, probe.usdt)

		probes = append(probes, probe)
	}

	return &RubyLinuxCollector{
		probes: probes,
	}, nil
}

func mutateUSDTArgumentInstructions(probe *collectorProbe, providerName string, symbolName string, spec *ebpf.ProgramSpec) error {
	providerNameC := C.CString(providerName)
	probeName := C.CString(symbolName)
	locationIndex := C.int(0)

	argSpecs := []C.struct_bcc_usdt_argument{}
	for argumentIndex := 0; ; argumentIndex++ {
		var cArgSpec C.struct_bcc_usdt_argument
		ret := C.bcc_usdt_get_argument(probe.usdt, providerNameC, probeName, locationIndex, C.int(argumentIndex), &cArgSpec)
		if ret != 0 {
			break
		}
		if cArgSpec.valid&C.BCC_USDT_ARGUMENT_BASE_REGISTER_NAME != 0 {
			argSpecs = append(argSpecs, cArgSpec)
		} else {
			return fmt.Errorf("arg spec for %v contained unsupported spec: %v", symbolName, cArgSpec)
		}
	}

	if len(argSpecs) == 0 {
		return nil
	}

	/*
			  This is a hack, but we produce the following:
		         1: LdXMemDW dst: r1 src: r6 off: 152 imm: 0
		         2: MovReg dst: r3 src: r1
		         3: AddImm dst: r3 imm: 65280
			  We want to adjust the LdXMemDW to load the offset for the correct register and AddImm the correct offset from there.
	*/
	adjustments := 0
	for i := 0; i < len(spec.Instructions); i++ {
		ins := spec.Instructions[i]
		if i+3 >= len(spec.Instructions) {
			continue
		}
		movIns := spec.Instructions[i+1]
		addIns := spec.Instructions[i+2]

		if ins.OpCode.String() != "LdXMemDW" {
			continue
		}

		if movIns.OpCode.String() != "MovReg" {
			continue
		}

		if addIns.OpCode.String() != "AddImm" {
			continue
		}

		// the final destination is expected to be r3 as the final argument to bpf_probe_read
		if movIns.Dst != addIns.Dst || addIns.Dst.String() != "r3" {
			continue
		}

		argumentIndex := int(addIns.Constant & 0xff)

		if argumentIndex < 0 || argumentIndex >= len(argSpecs) {
			return fmt.Errorf("asm contained reference to argument that was out of range (referenced %v, expected was %v)", argumentIndex, len(argSpecs))
		}

		argSpec := argSpecs[argumentIndex]
		argOffset := C._offset_for_usdt_arg(&argSpec)

		if argSpec.valid != C.BCC_USDT_ARGUMENT_BASE_REGISTER_NAME|C.BCC_USDT_ARGUMENT_DEREF_OFFSET &&
			argSpec.valid != C.BCC_USDT_ARGUMENT_BASE_REGISTER_NAME {
			return fmt.Errorf("Unsupported USDT argument spec (flags %v)", argSpec.valid)
		}

		// update the offset in the context struct to the correct register
		ins.Offset = int16(argOffset)

		size := int64(argSpec.size)
		if size < 0 {
			size = -size
		}

		asmSize := asm.DWord
		if size != 8 {
			return fmt.Errorf("Expected USDT argument to be of size 8, others not supported yet")
		}

		// update the offset from the register to the data
		addIns.Constant = 0
		if argSpec.valid&C.BCC_USDT_ARGUMENT_DEREF_OFFSET != 0 {
			// we are doing the full (already encoded) deref, so update the offset
			addIns.Constant = int64(argSpec.deref_offset)
		} else {
			// we aren't doing a dereference, just using the register.

			// search ahead for the call to bpf_probe_read
			var probeReadOffset = 0
			for j := i + 3; j < len(spec.Instructions); j++ {
				ins := spec.Instructions[j]
				if ins.OpCode.String() == "Call" && ins.Constant == 4 {
					probeReadOffset = j
					break
				}
			}

			if probeReadOffset != 0 {
				// R3 would have been the address, which is the register value.
				// R1 would have been the output from the read
				// R0 would have contained the return value of the read (0, success)
				// this does:
				//   *R1 = R3
				//   R0 = 0
				spec.Instructions[probeReadOffset] = asm.StoreMem(asm.R1, 0, asm.R3, asmSize)
				spec.Instructions[probeReadOffset+1] = asm.Mov.Imm(asm.R0, 0) // "success"
			}
		}

		spec.Instructions[i] = ins
		spec.Instructions[i+2] = addIns
		if size != 8 {
			// annoyingly, the size specified in the argument list may be a smaller size than that specified in the probe.
			// so we awkwardly also update the read size providing it makes sense (is not longer)
			var lenArgOffset = 0
			for lenArg := i + 3; lenArg < len(spec.Instructions); lenArg++ {
				ins := spec.Instructions[lenArg]
				if ins.Dst.String() == "r2" {
					lenArgOffset = lenArg
					break
				}
			}

			if lenArgOffset == 0 {
				return fmt.Errorf("Could not find r2 write (read length argument) instruction")
			}

			if spec.Instructions[lenArgOffset].Constant > size {
				spec.Instructions[lenArgOffset].Constant = size
			} else if spec.Instructions[lenArgOffset].Constant < size {
				return fmt.Errorf("Argument specified in ELF notes is larger than compiled argument")
			}
		}

		adjustments++
	}

	if adjustments != len(argSpecs) {
		return fmt.Errorf("Expected to adjust %v arguments but only found %v", len(argSpecs), adjustments)
	}

	return nil
}

func fillCPUIndirectionMap(m *ebpf.Map) error {
	var values []uint32
	if err := m.Lookup(uint32(0), &values); err != nil {
		return fmt.Errorf("error while retrieving CPU heap index array from eBPF", err)
	}
	for i := 0; i < len(values); i++ {
		values[i] = uint32(i)
	}
	if err := m.Put(uint32(0), values); err != nil {
		return fmt.Errorf("error while placing CPU heap index array to eBPF", err)
	}

	return nil
}

func (u *RubyLinuxCollector) Start(out chan collectors.PendingSample) error {
	if err := setupEbpf(); err != nil {
		return err
	}

	// hook each configured PID
	for _, probe := range u.probes {
		// load a full copy of the eBPF reader programs/maps per program
		// we use an isolated set of program+maps so we can specify args
		// specific to the program, and avoid needing to map back to the
		// correct pid.
		spec, err := loadRubyEbpfReader()
		if err != nil {
			return fmt.Errorf("error while loading the spec: %v", err)
		}

		if err := mutateUSDTArgumentInstructions(probe, "tracecap_ruby_opentracing", "ruby__span", spec.Programs["tracecap_ruby__span"]); err != nil {
			return err
		}
		if err := mutateUSDTArgumentInstructions(probe, "tracecap_ruby_profiler", "ruby__sample__std", spec.Programs["tracecap_ruby__sample__std"]); err != nil {
			return err
		}

		var objs rubyEbpfReaderObjects
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			return fmt.Errorf("error while loading and assigning objects: %v", err)
		}

		if err := fillCPUIndirectionMap(objs.CpuToIndex); err != nil {
			return err
		}

		errSpan := u.installProbe(probe, "tracecap_ruby_opentracing", "ruby__span", objs.TracecapRubySpan)
		errProf := u.installProbe(probe, "tracecap_ruby_profiler", "ruby__sample__std", objs.TracecapRubySampleStd)

		if errSpan != nil && errProf != nil {
			return fmt.Errorf("error while attaching span=%v prof=%v", errSpan, errProf)
		} else if errSpan != nil {
			fmt.Printf("Error attaching span, but continuing with just profiling: %v\n", errSpan)
		} else if errProf != nil {
			fmt.Printf("Error attaching profiling, but continuing with just span: %v\n", errProf)
		}

		if errSpan == nil {
			go u.readSpanEvents(out, objs.SpanEvents)
		}

		if errProf == nil {
			go u.readProfileEvents(out, objs.ProfileEvents)
		}
	}

	return nil
}

func (u *RubyLinuxCollector) installProbe(probe *collectorProbe, providerName string, symbolName string, prog *ebpf.Program) error {
	providerNameC := C.CString(providerName)
	probeName := C.CString(symbolName)
	locationIndex := C.int(0)
	progFd := uint32(prog.FD())

	var loc C.struct_bcc_usdt_location
	ret := C.bcc_usdt_get_location(probe.usdt, providerNameC, probeName, locationIndex, &loc)
	if ret != 0 {
		return fmt.Errorf("Expected bcc_usdt_get_location to return 0, but returned %v", ret)
	}
	if C.bcc_usdt_enable_probe(probe.usdt, probeName, C.CString("tracecap_"+symbolName)) != 0 {
		return fmt.Errorf("Expected bcc_usdt_enable_probe to enable probe")
	}

	evName := "tracecap_" + symbolName // FIXME: use pattern from bcc

	efd := C.bpf_attach_uprobe(C.int(progFd), C.BPF_PROBE_ENTRY, C.CString(evName), loc.bin_path, loc.address, C.pid_t(probe.pid))
	if efd <= 0 {
		return fmt.Errorf("failed to attach uprobe, got: %v", efd)
	}

	probe.evName = evName

	return nil
}

func (u *RubyLinuxCollector) Stop() error {
	for _, probe := range u.probes {
		if probe.evName != "" {
			C.bpf_detach_uprobe(C.CString(probe.evName))
		}
		probe.evName = ""
	}

	if u.spanReader != nil {
		u.spanReader.Close()
	}

	return nil
}

func (u *RubyLinuxCollector) Close() {
	for _, probe := range u.probes {
		C.bcc_usdt_close(probe.usdt)
	}
}

func (u *RubyLinuxCollector) readProfileEvents(out chan collectors.PendingSample, eventMap *ebpf.Map) error {
	rd, err := ringbuffer.NewReader(eventMap, os.Getpagesize()*1280)
	if err != nil {
		return fmt.Errorf("error while creating ringbuffer reader: %v", err)
	}
	u.spanReader = rd

	var profile profileEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if ringbuffer.IsClosed(err) {
				log.Printf("Closed: %v\n", err)
				return nil
			}
			log.Printf("failed to read from ringbuffer: %+v\n", err)
		}
		if record.LostSamples != 0 {
			// log.Printf("lost samples due to ringbuffer full: %+v\n", record.LostSamples)
			u.dropped += record.LostSamples
			continue
		}

		binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &profile)

		objectSpaceData := &tracecappb.ObjectSpaceSample{
			Total: uint64(profile.ObjectSpaceTotal),
			Free:  uint64(profile.ObjectSpaceFree),
		}

		stringTrace := parseCString(profile.RubyStack[:])
		stack := parseStackTrace(stringTrace, true)

		sample := collectors.PendingSample{
			PID: int(profile.Pid),
			TID: int(profile.Tid),
			Sample: &tracecappb.ThreadSample{
				Scope:          tracecappb.SampleScope_VM_RUBY,
				Purpose:        tracecappb.SamplePurpose_PROFILE,
				CollectionTime: uint64(profile.TimeEmitNsec),
				Stack:          stack,
				ObjectSpace:    objectSpaceData,
			},
		}

		out <- sample
	}
}

func (u *RubyLinuxCollector) readSpanEvents(out chan collectors.PendingSample, eventMap *ebpf.Map) error {
	rd, err := ringbuffer.NewReader(eventMap, os.Getpagesize()*1280)
	if err != nil {
		return fmt.Errorf("error while creating ringbuffer reader: %v", err)
	}
	u.spanReader = rd

	var event spanEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if ringbuffer.IsClosed(err) {
				log.Printf("Closed: %v\n", err)
				return nil
			}
			log.Printf("failed to read from ringbuffer: %+v\n", err)
		}
		if record.LostSamples != 0 {
			// log.Printf("lost samples due to ringbuffer full: %+v\n", record.LostSamples)
			u.dropped += record.LostSamples
			continue
		}

		binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

		ec, metadata, err := parseContextBytes(event.SpanContext[:bytes.IndexByte(event.SpanContext[:], 0)])
		if err != nil {
			log.Printf("Failed to parse context bytes: %v\n", err)
			continue
		}

		var startTime uint64
		var endTime uint64
		endTime = event.TimeEmitNsec - event.EndDeltaNsec
		startTime = endTime - event.DurationNsec

		span_sample := &tracecappb.SpanSample{
			StartTime:     startTime,
			EndTime:       endTime,
			ComponentName: parseCString(event.SpanItem[:]),
			Description:   parseCString(event.SpanName[:]),
			Id:            ec.SpanID,
			ParentId:      ec.SpanParentID,
		}

		if ec.QueueDurationNs > 0 {
			span_sample.QueueTime = uint64(ec.QueueDurationNs)
		}

		stringTrace := parseCString(event.RubyStack[:])
		stack := parseStackTrace(stringTrace, true)

		thread_sample := &tracecappb.ThreadSample{
			Scope:          tracecappb.SampleScope_VM_RUBY,
			Purpose:        tracecappb.SamplePurpose_TRACE,
			CollectionTime: event.TimeEmitNsec,
			Stack:          stack,
			Span:           span_sample,
			Metadata:       metadata,
		}

		out <- collectors.PendingSample{
			PID:    int(event.Pid),
			TID:    int(event.Tid),
			Sample: thread_sample,
		}
	}
}

func (u *RubyLinuxCollector) Stats() collectors.SampleStats {
	return collectors.SampleStats{
		Dropped: u.dropped,
	}
}
