# 1. Telemetry is durable before it is acknowledged

## Context

v1's ingest endpoint accepted a batch, put it on a Redis list and answered
`durable: true`. Everything after that — the hot store, ClickHouse, the search
index — was reached by workers whose failures were invisible to the agent. The
agent's write-ahead spool, the one place that still had the data, had already
been told it could let go.

The agent's compatibility window is explicit that it drops a persisted batch
only on an acknowledgement that says `accepted` and `durable` with a matching
count. That promise is only worth something if the platform means it.

## Decision

The first durable destination for telemetry is the event backbone. The gateway
publishes with an idempotent producer and waits for every in-sync replica before
it answers. If the publish fails, times out or is cancelled, the agent gets
`503` and keeps its copy.

Nothing else happens on the request path. No database, no cache, no analytics,
no detection.

## Consequences

- The gateway is stateless and horizontally scalable.
- A backbone outage becomes visible backpressure at the agents, not silent loss.
- Delivery is at least once. Duplicate suppression is a consumer concern, keyed
  on the producer-assigned `event_id`.
- The gateway cannot report a duplicate it never saw, so the acknowledgement
  carries only what the gateway actually knows: accepted, durable, received.
- A slow backbone becomes a slow gateway. The publish budget is bounded by
  `SEAGULL_GATEWAY_PUBLISH_TIMEOUT` so requests cannot pile up without limit.
