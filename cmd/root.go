/*
Copyright © 2021 Theo Julienne <theojulienne@github.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"compress/gzip"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tracecap/tracecap/collectors"
	ruby_collector "github.com/tracecap/tracecap/collectors/ruby"
	"github.com/tracecap/tracecap/tracecappb"
	"google.golang.org/protobuf/proto"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/mitchellh/go-ps"
	"github.com/spf13/viper"
)

var cfgFile string
var rubyCollector []string

// type TraceFile struct {
// 	Traces []interface{}
// }

var globalId uint64 = 0

func EnsureProcess(tf *tracecappb.TraceFile, pid uint32) *tracecappb.Process {
	for _, proc := range tf.Processes {
		if proc.Pid == pid {
			return proc
		}
	}

	globalId++
	newProc := &tracecappb.Process{
		InternalId: globalId,
		Pid:        pid,
	}

	tf.Processes = append(tf.Processes, newProc)

	return newProc
}

func EnsureThread(tf *tracecappb.TraceFile, pid uint32, tid uint32) *tracecappb.Thread {
	proc := EnsureProcess(tf, pid)

	for _, thread := range proc.Threads {
		if thread.Tid == tid {
			return thread
		}
	}

	globalId++
	newThread := &tracecappb.Thread{
		InternalId: globalId,
		Tid:        tid,
	}

	proc.Threads = append(proc.Threads, newThread)

	return newThread
}

func parsePidList(arg []string) []int {
	outPids := []int{}
	for _, pidsString := range arg {
		pids := strings.Split(pidsString, "\n")
		for _, pidString := range pids {
			pid, err := strconv.Atoi(pidString)
			if err == nil {
				outPids = append(outPids, pid)
			}
		}
	}
	return outPids
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tracecap",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,

	Run: func(cmd *cobra.Command, args []string) {
		out := make(chan collectors.PendingSample, 32)

		sampleCollectors := []collectors.SampleCollector{}

		rubyPids := parsePidList(rubyCollector)
		if len(rubyPids) > 0 {
			rubyCollector, err := ruby_collector.NewRubyCollector(rubyPids)
			if err != nil {
				log.Fatal(err)
			}

			sampleCollectors = append(sampleCollectors, rubyCollector)
		}

		if len(sampleCollectors) == 0 {
			fmt.Printf("No collectors specified\n")
			return
		}

		traceData := &tracecappb.TraceFile{}

		mainCollector := collectors.NewMultipleSampleCollector(sampleCollectors)
		defer mainCollector.Close()

		err := mainCollector.Start(out)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Tracing...\n")

		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
		signal.Notify(stopper, os.Interrupt, syscall.SIGINT)

		timer := time.NewTimer(10 * time.Second)

		for running := true; running; {
			select {
			case ps := <-out:
				thread := EnsureThread(traceData, uint32(ps.PID), uint32(ps.TID))

				sample := ps.Sample
				sample.ThreadInternalId = thread.InternalId
				traceData.Samples = append(traceData.Samples, sample)
			case <-timer.C:
				fmt.Println("Completed after 10 seconds.")
				running = false
			case <-stopper:
				fmt.Println("Completed after signal.")
				running = false
			}
		}

		mainCollector.Stop()

		// now fill in process information. later, this should happen inline
		for _, proc := range traceData.Processes {
			pd, err := ps.FindProcess(int(proc.Pid))
			if err == nil && pd != nil {
				proc.ExecName = pd.Executable()
			}
		}

		stats := mainCollector.Stats()

		fmt.Printf("Writing %v traces (%v samples lost).\n", len(traceData.Samples), stats.Dropped)

		data, err := proto.Marshal(traceData)
		if err != nil {
			log.Fatal(err)
		}
		file, err := os.Create("capture.tcap")
		if err != nil {
			log.Fatal(err)
		}

		zw := gzip.NewWriter(file)
		_, err = zw.Write(data)
		if err != nil {
			log.Fatal(err)
		}

		zw.Close()
		file.Close()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.tracecap.yaml)")

	rootCmd.PersistentFlags().StringArrayVar(&rubyCollector, "ruby", []string{}, "enable the ruby collector with one or more pids")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetConfigType("yaml")

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".tracecap" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".tracecap")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		// fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
