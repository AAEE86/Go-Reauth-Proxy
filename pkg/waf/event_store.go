package waf

import (
	"sync"
	"time"
)

type EventStore struct {
	mu         sync.Mutex
	items      map[string]storedEvent
	order      []string
	maxEntries int
	ttl        time.Duration
}

type storedEvent struct {
	event     Event
	expiresAt time.Time
}

func NewEventStore(maxEntries int, ttl time.Duration) *EventStore {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEvents
	}
	if ttl <= 0 {
		ttl = DefaultEventTTL
	}
	return &EventStore{
		items:      make(map[string]storedEvent),
		order:      []string{},
		maxEntries: maxEntries,
		ttl:        ttl,
	}
}

func (s *EventStore) Add(event Event) {
	if s == nil || event.TraceID == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if _, exists := s.items[event.TraceID]; !exists {
		s.order = append(s.order, event.TraceID)
	}
	s.items[event.TraceID] = storedEvent{
		event:     event,
		expiresAt: now.Add(s.ttl),
	}
	for len(s.order) > s.maxEntries {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.items, oldest)
	}
}

func (s *EventStore) Pending() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	return len(s.items)
}

func (s *EventStore) Drain(limit int) DrainResult {
	if s == nil {
		return DrainResult{Events: []Event{}}
	}
	if limit <= 0 || limit > s.maxEntries {
		limit = s.maxEntries
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())

	events := make([]Event, 0, min(limit, len(s.order)))
	for len(s.order) > 0 && len(events) < limit {
		id := s.order[0]
		s.order = s.order[1:]
		if item, ok := s.items[id]; ok {
			events = append(events, item.event)
			delete(s.items, id)
		}
	}
	return DrainResult{
		Events:    events,
		Drained:   len(events),
		Remaining: len(s.items),
	}
}

func (s *EventStore) cleanupLocked(now time.Time) {
	if len(s.order) == 0 {
		return
	}
	next := s.order[:0]
	for _, id := range s.order {
		item, ok := s.items[id]
		if !ok {
			continue
		}
		if now.After(item.expiresAt) {
			delete(s.items, id)
			continue
		}
		next = append(next, id)
	}
	s.order = next
}
