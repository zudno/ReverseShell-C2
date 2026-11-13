// Command listener runs a standalone remote listener: it terminates implant
// connections and relays frames to the teamserver over the relay plane.
//
// F0 placeholder: the relay protocol lands in F4. Until then, the embedded
// listener inside the teamserver is the default.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		host       = flag.String("host", "127.0.0.1", "session listener bind address")
		port       = flag.Int("port", 4444, "session listener port")
		teamserver = flag.String("teamserver", "127.0.0.1:5556", "teamserver relay address")
	)
	flag.Parse()

	fmt.Fprintln(os.Stderr, "listener: F0 placeholder — relay plane lands in F4")
	fmt.Fprintf(os.Stderr, "configured: bind %s:%d, upstream %s\n", *host, *port, *teamserver)
	os.Exit(1)
}
