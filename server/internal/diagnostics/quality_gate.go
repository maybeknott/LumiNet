package diagnostics

import (
	"context"
	"fmt"
	"log"
)

// QualityGateStatus represents the status of a specific check.
type QualityGateStatus string

const (
	StatusPending QualityGateStatus = "PENDING"
	StatusPassed  QualityGateStatus = "PASSED"
	StatusFailed  QualityGateStatus = "FAILED"
)

// QualityGate represents a state machine for automated diagnostic sequences.
type QualityGate struct {
	Name    string
	Checks  []*GateCheck
	Context context.Context
}

// GateCheck is a single step in the quality gate sequence.
type GateCheck struct {
	ID          string
	Description string
	Status      QualityGateStatus
	Error       error
	RunFn       func(ctx context.Context) error
}

func NewQualityGate(ctx context.Context, name string) *QualityGate {
	return &QualityGate{
		Name:    name,
		Checks:  make([]*GateCheck, 0),
		Context: ctx,
	}
}

func (q *QualityGate) AddCheck(id, desc string, runFn func(ctx context.Context) error) {
	q.Checks = append(q.Checks, &GateCheck{
		ID:          id,
		Description: desc,
		Status:      StatusPending,
		RunFn:       runFn,
	})
}

// Run executes all checks sequentially. If one fails, the sequence halts.
func (q *QualityGate) Run() error {
	log.Printf("Starting Quality Gate: %s", q.Name)
	for i, check := range q.Checks {
		log.Printf("[%d/%d] Running check: %s (%s)", i+1, len(q.Checks), check.ID, check.Description)
		
		if err := check.RunFn(q.Context); err != nil {
			check.Status = StatusFailed
			check.Error = err
			log.Printf("Check %s FAILED: %v", check.ID, err)
			return fmt.Errorf("quality gate %s failed at %s: %w", q.Name, check.ID, err)
		}
		
		check.Status = StatusPassed
		log.Printf("Check %s PASSED", check.ID)
	}
	
	log.Printf("Quality Gate %s PASSED all %d checks", q.Name, len(q.Checks))
	return nil
}
