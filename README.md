# tracecap

tracecap hooks programs via USDT to export certain high fidelity traces with rich information like context and backtraces at a higher frequency than would be reasonable with distributed tracing.

The following exporter plugins are currently supported:
 * https://github.com/tracecap/tracecap-ruby-opentracing
 * https://github.com/tracecap/tracecap-ruby-profiler

# Recording a trace in Ruby

With the above exporters installed, run tracecap with the Ruby collector on a set of one or more Ruby processes:
```
$ sudo tracecap --ruby "$(pgrep ruby)"
```

This will create a `capture.tcap` which can be uploaded to the UI.

# Uploading to the tracecap viewer

[tracecap.app](https://tracecap.app) provides the interface to view traces on a timeline. Log in with GitHub, go to your user or org space, then click Upload. You can upload a capture file directly on this page, or use a push token to push from the CLI by following the instructions.

To configure the CLI to use the push token, run the following and paste in the equivalent push token provided in the UI:
```
$ tracecap login tracecap.app/github.com/<your-user-or-org>
```

You can then upload a tcap:
```
$ tracecap login tracecap.app/github.com/<your-user-or-org> capture.tcap
Uploading tcap...
Trace has been uploaded successfully! You can view it at:

   URL: https://tracecap.app/github.com/<your-user-or-org>/ui/?q=load%20<trace-id>

   Query: load <trace-id>

```

You can either click the URL or paste in the query to the UI under your project.
