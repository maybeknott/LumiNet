package relay

import (
	"errors"
	"strings"
	"sync"
)

type PipelineVerdictType string

const (
	VerdictPassThrough   PipelineVerdictType = "PassThrough"
	VerdictShortCircuit  PipelineVerdictType = "ShortCircuit"
	VerdictModifyHeaders PipelineVerdictType = "ModifyHeaders"
)

type HeaderPair struct {
	Key   string
	Value string
}

type PipelineVerdict struct {
	Type       PipelineVerdictType
	StatusCode int
	Body       []byte
	Headers    []HeaderPair
}

type ProxyFilterHook interface {
	OnRequest(method, path string, headers []HeaderPair) PipelineVerdict
}

type HeaderInjectorHook struct {
	HeaderName  string
	HeaderValue string
}

func NewHeaderInjectorHook(name, value string) *HeaderInjectorHook {
	return &HeaderInjectorHook{
		HeaderName:  name,
		HeaderValue: value,
	}
}

func (h *HeaderInjectorHook) OnRequest(method, path string, headers []HeaderPair) PipelineVerdict {
	return PipelineVerdict{
		Type: VerdictModifyHeaders,
		Headers: []HeaderPair{
			{Key: h.HeaderName, Value: h.HeaderValue},
		},
	}
}

type BlockPathHook struct {
	BlockedPrefix string
}

func NewBlockPathHook(prefix string) *BlockPathHook {
	return &BlockPathHook{
		BlockedPrefix: prefix,
	}
}

func (b *BlockPathHook) OnRequest(method, path string, headers []HeaderPair) PipelineVerdict {
	if strings.HasPrefix(path, b.BlockedPrefix) {
		return PipelineVerdict{
			Type:       VerdictShortCircuit,
			StatusCode: 403,
			Body:       []byte("Forbidden by LumiProxy Pipeline"),
		}
	}
	return PipelineVerdict{Type: VerdictPassThrough}
}

type ProgrammableProxyPipeline struct {
	mu    sync.RWMutex
	hooks []ProxyFilterHook
}

func NewProgrammableProxyPipeline() *ProgrammableProxyPipeline {
	return &ProgrammableProxyPipeline{
		hooks: make([]ProxyFilterHook, 0),
	}
}

func (p *ProgrammableProxyPipeline) AddHook(hook ProxyFilterHook) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hooks = append(p.hooks, hook)
}

func (p *ProgrammableProxyPipeline) ProcessRequest(method, path string, headers *[]HeaderPair) (int, []byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, hook := range p.hooks {
		v := hook.OnRequest(method, path, *headers)
		switch v.Type {
		case VerdictPassThrough:
			// continue
		case VerdictShortCircuit:
			return v.StatusCode, v.Body, errors.New("short circuited")
		case VerdictModifyHeaders:
			*headers = append(*headers, v.Headers...)
		}
	}

	return 200, nil, nil
}
