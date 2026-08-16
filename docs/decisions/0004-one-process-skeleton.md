# 4. Every process starts from the same skeleton

## Context

A platform that will grow to seven or eight executables cannot have each one
inventing its own logging, metrics, health, signal handling and shutdown. v1's
answer was a single process where everything was shared by being global; that is
why its readiness report, its metric registry and its configuration ended up
without an owner.

## Decision

`internal/platform/service` builds what every process needs: a configured
logger, one metric registry, a readiness registry, the operational listener and
a run group. An executable adds its own components and calls `Run`.

`internal/platform/run` owns lifecycle. A component is anything with a name and
a `Run(ctx) error` that returns when its context is cancelled. The group starts
every component, and the first one to return — or a signal — stops the rest.
Shutdown is bounded; a component that will not stop is reported by name rather
than waited on forever.

Instruments are created once per process and shared by every listener. The route
label distinguishes them.

## Consequences

- A new executable is a `main.go` that loads configuration and adds components.
  `control-api` exists mainly to prove this, and it is 100 lines.
- Graceful shutdown, signal handling, readiness draining and metric exposition
  are properties of the foundation, so no component can forget them.
- One ownership rule replaced a class of bug: the first time both listeners were
  built in one process they registered the same collectors twice and the process
  panicked at startup. The end-to-end suite now builds the process the way the
  executable does, so the next such mistake fails a test.
- The operational surface — `/healthz`, `/readyz`, `/metrics` — is a separate
  listener on a separate address, bound to loopback by default. Keeping it off
  the public edge is structural rather than a proxy rule that has to be repeated
  in every deployment.
