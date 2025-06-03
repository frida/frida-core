package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	tscore "github.com/frida/typescript-go/pkg/core"
	"github.com/frida/typescript-go/pkg/tsoptions"
	"github.com/frida/typescript-go/pkg/tspath"
)

type TSConfigCache struct {
	projectRoot  string
	sourceMap    bool
	tsconfigPath string
	onChange     ConfigChangeCallback

	mu          sync.Mutex
	lastModTime time.Time
	cachedOpts  *tscore.CompilerOptions
	lastText    string
}

type ConfigChangeCallback func()

func NewTSConfigCache(
	projectRoot string,
	sourceMap bool,
	callback ConfigChangeCallback,
) *TSConfigCache {
	return &TSConfigCache{
		projectRoot:  projectRoot,
		sourceMap:    sourceMap,
		tsconfigPath: filepath.Join(projectRoot, "tsconfig.json"),
		lastModTime:  time.Time{},
		cachedOpts:   nil,
		lastText:     "",
		onChange:     callback,
	}
}

func (c *TSConfigCache) GetCompilerOptions(
	host tsoptions.ParseConfigHost,
) (*tscore.CompilerOptions, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fs := host.FS()

	info := fs.Stat(c.tsconfigPath)
	var currentModTime time.Time
	if info != nil {
		currentModTime = info.ModTime()
	} else {
		currentModTime = time.Time{}
	}

	if c.cachedOpts != nil && currentModTime.Equal(c.lastModTime) {
		return c.cachedOpts, c.lastText, nil
	}

	var tsconfigText string
	if info != nil {
		data, ok := fs.ReadFile(c.tsconfigPath)
		if !ok {
			return nil, "", fmt.Errorf("Unable to read %q", c.tsconfigPath)
		}
		tsconfigText = string(data)
	} else {
		tsconfigText = "{}"
	}

	parsedSource := tsoptions.NewTsconfigSourceFileFromFilePath(
		tspath.NormalizePath(c.tsconfigPath),
		tspath.ToPath(c.tsconfigPath, "", fs.UseCaseSensitiveFileNames()),
		tsconfigText,
	)
	parsedCommandLine := tsoptions.ParseJsonSourceFileConfigFileContent(
		parsedSource,
		host,
		c.projectRoot,
		nil,
		c.tsconfigPath,
		nil, nil, nil,
	)

	if len(parsedCommandLine.Errors) > 0 {
		var msgs []string
		for _, diag := range parsedCommandLine.Errors {
			msgs = append(msgs, diag.Message())
		}
		return nil, "", fmt.Errorf(
			"Failed to parse %s: %s",
			c.tsconfigPath,
			strings.Join(msgs, "; "),
		)
	}

	newOpts := parsedCommandLine.CompilerOptions()
	newOpts.Module = tscore.ModuleKindNode16
	newOpts.ModuleResolution = tscore.ModuleResolutionKindNode16
	newOpts.NoEmit = tscore.TSFalse

	sourceMapOptVal := boolToTristate(c.sourceMap)
	newOpts.SourceMap = sourceMapOptVal
	newOpts.InlineSourceMap = sourceMapOptVal

	if newOpts.Target == tscore.ScriptTargetNone {
		newOpts.Target = tscore.ScriptTargetES2022
	}
	if newOpts.Lib == nil {
		newOpts.Lib = []string{"lib.es2022.d.ts"}
	}
	if newOpts.SkipLibCheck == tscore.TSUnknown {
		newOpts.SkipLibCheck = tscore.TSTrue
	}
	if newOpts.Strict == tscore.TSUnknown {
		newOpts.Strict = tscore.TSTrue
	}

	tsconfigData, _ := json.Marshal(parsedCommandLine.ParsedConfig)
	tsconfigText = string(tsconfigData)

	hadPreviousOpts := c.cachedOpts != nil
	optsChanged := true
	if c.cachedOpts != nil && reflect.DeepEqual(newOpts, c.cachedOpts) {
		optsChanged = false
	}

	if optsChanged {
		c.cachedOpts = newOpts
		c.lastText = tsconfigText
	}
	c.lastModTime = currentModTime

	c.mu.Unlock()
	defer c.mu.Lock()

	if hadPreviousOpts && optsChanged {
		if c.onChange != nil {
			c.onChange()
		}
	}

	return newOpts, tsconfigText, nil
}

func boolToTristate(val bool) tscore.Tristate {
	if val {
		return tscore.TSTrue
	}
	return tscore.TSFalse
}
