---
title: "Architecture"
weight: 20
---

# Architecture

Project Gaia uses a distributed architecture with edge devices (Farms) and a central aggregator (Hub).

## Components

### Farm
The Farm component runs on-site and interacts with sensors and actuators. It is responsible for local data storage and execution of local rules.

### Hub
The Hub is a cloud-based service that aggregates data from multiple Farms, providing a unified dashboard and enabling cross-farm cooperation.

### Communication
Communication between Farms and the Hub is secured via **mTLS**. GraphQL is used as the primary API protocol.
