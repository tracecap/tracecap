package ruby

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/tracecap/tracecap/tracecappb"
)

type ExtraContext struct {
	SpanID          string `json:"span_id"`
	SpanParentID    string `json:"span_parent_id"`
	QueueDurationNs uint64 `json:"timing.queue_duration_ns"`
}

func parseContextBytes(context []byte) (*ExtraContext, []*tracecappb.Metadata, error) {
	ec := &ExtraContext{}
	json.Unmarshal(context, ec)

	var metaItems map[string]interface{}
	err := json.Unmarshal(context, &metaItems)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to decode: %v from '%v'\n", err, context)
	}

	metadata := []*tracecappb.Metadata{}
	for k, v := range metaItems {
		if k == "span_id" || k == "span_parent_id" || k == "timing.queue_duration_ns" {
			continue
		}

		switch val := v.(type) {
		case string:
			m := &tracecappb.Metadata{
				Name:  k,
				Value: &tracecappb.Metadata_MetaString{MetaString: val},
			}

			metadata = append(metadata, m)
		case []interface{}:
			for _, item := range val {
				switch subval := item.(type) {
				case string:
					m := &tracecappb.Metadata{
						Name:  k,
						Value: &tracecappb.Metadata_MetaString{MetaString: subval},
					}

					metadata = append(metadata, m)
				}
			}
		}
	}

	return ec, metadata, nil
}

func parseStackTrace(stacktrace string, reversed bool) *tracecappb.StackSample {
	stack := &tracecappb.StackSample{}
	traceLines := strings.Split(stacktrace, "\n")
	for _, line := range traceLines {
		pieces := strings.SplitN(line, ":", 4)
		if len(pieces) != 4 {
			continue
		}
		// package:filename:line:method
		lineno, _ := strconv.Atoi(pieces[2])
		frame := &tracecappb.StackFrame{
			File:   pieces[1],
			Line:   uint32(lineno),
			Method: pieces[3],
		}
		if pieces[0] != "" {
			frame.Package = pieces[0]
		}
		stack.Stack = append(stack.Stack, frame)
	}
	if reversed {
		reversedStack := &tracecappb.StackSample{}
		for i := 0; i < len(stack.Stack); i++ {
			reversedStack.Stack = append(reversedStack.Stack, stack.Stack[len(stack.Stack)-1-i])
		}
		return reversedStack
	} else {
		return stack
	}
}

func parseCString(b []byte) string {
	return string(b[:bytes.IndexByte(b, 0)])
}
