# JZT Integration Boundary

[中文](JZT_INTEGRATION.md) | [English](JZT_INTEGRATION.en.md)

## Principle

The JZT connection is an adapter and must never write `stock` or `gsp_batch_stock` directly. An internal business
transaction commits its controlled state and an associated `gsp_integration_outbox` event in the same database
transaction. A background sender then delivers, retries, and reconciles by deterministic idempotency key. Incoming
receipts must retain the original payload before an application service validates any state transition.

This repository currently implements adapter-neutral outbox governance: canonical-payload SHA-256 idempotency,
concurrent claims, exponential backoff, dead-letter state, and electronically signed/audited manual replay. The JZT
network client, authentication/signature scheme, field mapping, inbound receipts, and formal reconciliation are
intentionally excluded until specifications and a test environment are supplied.

## Information Required Before Development

- test and production endpoints, allowlists, TLS and certificate requirements;
- authentication, signatures, timestamps, anti-replay rules and key rotation;
- product, customer, warehouse, batch, unit and status code tables;
- order, shipment, acceptance, inventory, return and trace-code payload specifications and examples;
- synchronous/asynchronous behavior, timeouts, limits, retry windows, errors and compensation rules;
- business keys, versioning, idempotency and change-notification rules;
- daily reconciliation files, discrepancy handling, historical replay and manual-intervention procedures.

## Candidate Messages

| Message | Direction | Internal trigger |
|---|---|---|
| `PRODUCT_MASTER_CHANGED` | WMS → JZT | Product quality approval |
| `PARTNER_QUALIFIED` | WMS → JZT | Partner quality approval |
| `PURCHASE_ORDER_RECEIVED` | JZT → WMS | Validated external purchase/distribution order |
| `BATCH_ACCEPTED` | WMS → JZT | Receipt acceptance and release |
| `SHIPMENT_CONFIRMED` | WMS → JZT | Independent dispatch review and actual shipment |
| `INVENTORY_SNAPSHOT` | WMS → JZT | Daily or agreed periodic snapshot |
| `STOCKTAKE_COMPLETED` | WMS → JZT | Reviewed count or executed approved adjustment |
| `SALES_RETURN_RECEIVED` | WMS → JZT | Return linked to original shipment and quarantined |
| `SALES_RETURN_INSPECTED` | WMS → JZT | Independent return inspection decision |
| `NONCONFORMING_DISPOSITION_APPROVED` | WMS → JZT | Independent disposition approval |
| `NONCONFORMING_DESTROYED` | WMS → JZT | Witnessed destruction evidence registered |
| `PURCHASE_RETURN_DISPATCHED` | WMS → JZT | Approved supplier return shipped and decremented |
| `RECALL_ACTIVATED` | WMS → JZT | Recall approved and batches held |
| `RECALL_TARGET_UPDATED` | WMS → JZT | Notification or recovered quantity updated |
| `RECALL_CLOSED` | WMS → JZT | Quantity reconciliation and independent closure |
| `MAINTENANCE_PLAN_COMPLETED` | WMS → JZT | Maintenance checks independently reviewed |

Recall exercises are internal quality activities and do not use real recall messages unless the final interface
specification explicitly requires a dedicated exercise message.
