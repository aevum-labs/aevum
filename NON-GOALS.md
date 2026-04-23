# Non-Goals

This document defines what Aevum will never become. It is normative — these
boundaries are enforced by the RFC process and unanimous maintainer approval
is required to change them.

Reading this document before proposing a feature will save everyone time.

## Aevum is not a data integration platform

Aevum does not move data between systems, transform schemas, or replace tools
like Airbyte, Fivetran, dbt, or MuleSoft. Connectors (complications) may ingest
data from external sources, but Aevum does not manage pipelines.

## Aevum is not an AI orchestration framework

Aevum does not chain prompts, manage agent loops, or replace tools like LangChain,
LlamaIndex, or AutoGen. The `query` function assembles context for AI consumers;
it does not orchestrate them.

## Aevum is not a compliance report generator

Aevum produces audit trails that can be used as evidence for compliance purposes.
It does not generate compliance reports, interpret regulations, or provide legal
advice. The episodic ledger is a technical artefact, not a legal document.

## Aevum is not a knowledge graph database

Aevum uses a graph internally to represent relationships between entities. It is
not a general-purpose graph database and does not expose a Cypher, Gremlin, or
SPARQL endpoint to end users. Graph query is an implementation detail of the
`query` function.

## Aevum is not an agent execution environment

Aevum governs agents operating through its membrane — it does not schedule,
run, or host them. Agents are external; they call Aevum's five functions like
any other consumer.

## Aevum is not a streaming message broker

Aevum does not replace Kafka, Pulsar, or NATS. Events are appended to the
episodic ledger; they are not streamed to consumers in real time. Complications
may bridge to streaming systems, but Aevum itself is not one.

## Aevum is not an observability backend

Aevum emits OpenTelemetry spans and metrics. It does not store or visualize them.
Datadog, Grafana, Honeycomb, and similar tools remain the right place for that.

## Aevum is not an identity provider

Aevum resolves identity at query time through the OIDC complication. It never
stores credentials, issues tokens, or replaces your IDP. Auth is consumed, not
provided.

## Aevum is not a general-purpose policy engine

OPA and Cedar are embedded to govern Aevum's own operations. They are not
exposed as a general policy evaluation service. If you need a policy engine,
use OPA or Cedar directly.
