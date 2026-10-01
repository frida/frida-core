package main

import (
	"runtime"

	"github.com/frida/frida-core-compiler/patterns"
)

func describePatterns(source string, platform string, arch string) string {
	return patterns.DescribeSource(source, targetFor(platform, arch))
}

func decodePattern(source string, typeName string, data []byte, address uint64, platform string, arch string, inputs map[string]any) (string, error) {
	return patterns.DecodeSource(source, typeName, data, address, targetFor(platform, arch), inputs)
}

func callPatternFunction(source string, typeName string, data []byte, address uint64, platform string, arch string, inputs map[string]any,
	patternID int, functionName string) (string, error) {
	return patterns.CallFunctionSource(source, typeName, data, address, targetFor(platform, arch), inputs, patternID, functionName)
}

func targetFor(platform string, arch string) patterns.Target {
	if platform == "" {
		platform = hostPlatform()
	}
	if arch == "" {
		arch = hostArch()
	}
	switch arch {
	case "x64", "arm64":
		return patterns.Targets[0]
	case "ia32":
		if platform == "windows" {
			return patterns.Targets[1]
		}
		return patterns.Targets[2]
	}
	return patterns.Targets[1]
}

func hostPlatform() string {
	switch runtime.GOOS {
	case "ios":
		return "darwin"
	}
	return runtime.GOOS
}

func hostArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	}
	return runtime.GOARCH
}
