package privilege

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

const capNetRaw = 13

type osChecker struct{}

func (osChecker) Check() (bool, string) {
	if os.Geteuid() == 0 {
		return true, "root"
	}
	if hasCap(capNetRaw) {
		return true, "CAP_NET_RAW"
	}
	return false, ""
}

func hasCap(bit uint) bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		return v&(1<<bit) != 0
	}
	return false
}
