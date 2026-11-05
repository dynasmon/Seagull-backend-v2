package main

import (
	"log/slog"

	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
)

type sinks struct {
	events      ingest.Backbone
	inventory   ingest.InventoryBackbone
	status      ingest.StatusBackbone
	assessments ingest.AssessmentBackbone
}

// Every stream the gateway serves, built from its settings alone: what a stream
// admits and what the descriptor says of it are the same numbers.
func routes(settings configuration, into sinks, roster ingest.Roster, currency ingest.Current, registry *metrics.Registry, logger *slog.Logger) (ingest.ServerOptions, error) {
	instruments := ingest.NewMetrics(registry)
	admitter, err := ingest.NewAdmitter(into.events, settings.admissionRules, instruments)
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	inventoryInstruments := ingest.NewInventoryMetrics(registry)
	inventoryAdmitter, err := ingest.NewInventoryAdmitter(into.inventory, settings.inventoryRules, inventoryInstruments)
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	statusInstruments := ingest.NewStatusMetrics(registry)
	statusAdmitter, err := ingest.NewStatusAdmitter(into.status, settings.statusRules, statusInstruments)
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	assessmentInstruments := ingest.NewAssessmentMetrics(registry)
	assessmentAdmitter, err := ingest.NewAssessmentAdmitter(into.assessments, settings.assessments, assessmentInstruments)
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	capacity, err := ingest.NewCapacity(settings.maxInflightBytes, settings.maxInflightRequests)
	if err != nil {
		return ingest.ServerOptions{}, err
	}
	ingest.ObserveCapacity(registry, capacity)

	// One limiter and one capacity across every route: what an agent may spend
	// and what the process may hold are bounded per agent and per process, not
	// per kind of record, or a collector would buy a second budget by sending an
	// inventory batch or a status report.
	var limiter *ratelimit.Limiter
	if settings.rateLimited {
		limiter = ratelimit.NewLimiter(settings.ratePerSecond, settings.rateBurst, settings.trackedAgents)
	} else {
		logger.Warn("rate_limit_off", slog.String("setting", rateSetting))
	}

	handler, err := ingest.NewHandler(ingest.HandlerOptions{
		Admitter:       admitter,
		Roster:         roster,
		Currency:       currency,
		Limiter:        limiter,
		Capacity:       capacity,
		Metrics:        instruments,
		MaxBodyBytes:   settings.maxBodyBytes,
		PublishTimeout: settings.publishTimeout,
	})
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	inventoryHandler, err := ingest.NewInventoryHandler(ingest.InventoryHandlerOptions{
		Admitter:       inventoryAdmitter,
		Roster:         roster,
		Currency:       currency,
		Limiter:        limiter,
		Capacity:       capacity,
		Metrics:        inventoryInstruments,
		MaxBodyBytes:   settings.maxBodyBytes,
		PublishTimeout: settings.publishTimeout,
	})
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	statusHandler, err := ingest.NewStatusHandler(ingest.StatusHandlerOptions{
		Admitter:       statusAdmitter,
		Roster:         roster,
		Currency:       currency,
		Limiter:        limiter,
		Capacity:       capacity,
		Metrics:        statusInstruments,
		MaxBodyBytes:   settings.maxBodyBytes,
		PublishTimeout: settings.publishTimeout,
	})
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	assessmentHandler, err := ingest.NewAssessmentHandler(ingest.AssessmentHandlerOptions{
		Admitter:       assessmentAdmitter,
		Roster:         roster,
		Currency:       currency,
		Limiter:        limiter,
		Capacity:       capacity,
		Metrics:        assessmentInstruments,
		MaxBodyBytes:   settings.maxBodyBytes,
		PublishTimeout: settings.publishTimeout,
	})
	if err != nil {
		return ingest.ServerOptions{}, err
	}

	return ingest.ServerOptions{Handler: handler, Inventory: inventoryHandler, Status: statusHandler, Assessments: assessmentHandler}, nil
}
