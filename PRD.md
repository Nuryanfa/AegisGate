# AegisGate

## Distributed API Gateway & Security Platform

**Project Type:** Backend / Cloud-Native / Cybersecurity  
**Primary Language:** Go  
**Project Status:** Planning  
**Target:** Portfolio-grade production-like system  
**Version:** 1.0

---

# 1. Executive Summary

AegisGate adalah platform **API Gateway berbasis Go** yang bertindak sebagai lapisan perantara antara client dan backend services.

Selain melakukan routing dan reverse proxy, AegisGate dirancang untuk menyediakan fungsi:

- authentication,
- authorization,
- rate limiting,
- traffic management,
- Web Application Firewall,
- security detection,
- observability,
- centralized logging,
- service health monitoring,
- dan real-time security analytics.

Tujuan utama AegisGate bukan hanya membuat API Gateway sederhana, tetapi membangun sistem yang memperlihatkan bagaimana sebuah **production-grade edge service** dapat melindungi dan mengelola trafik menuju backend services.

AegisGate akan dirancang menggunakan prinsip:

- modular architecture,
- concurrent processing,
- fault tolerance,
- observability,
- security by design,
- horizontal scalability,
- dan cloud-native deployment.

---

# 2. Problem Statement

Modern application sering terdiri dari banyak backend service.

Contoh:

```text
Frontend
   │
   ├── Auth Service
   ├── User Service
   ├── Order Service
   ├── Payment Service
   └── Notification Service
```

Jika frontend mengakses semua service tersebut secara langsung, muncul beberapa masalah.

### Masalah 1 — Banyak endpoint

Frontend perlu mengetahui alamat setiap backend service.

Contoh:

```text
auth.example.com
user.example.com
order.example.com
payment.example.com
```

Hal ini meningkatkan coupling antara frontend dan backend infrastructure.

---

### Masalah 2 — Authentication tersebar

Setiap service harus mengimplementasikan authentication sendiri.

Akibatnya:

- terjadi duplikasi logic,
- konfigurasi security tidak konsisten,
- maintenance lebih sulit.

---

### Masalah 3 — Tidak ada centralized security control

Tanpa gateway, sulit melakukan centralized protection terhadap:

- brute force,
- API abuse,
- credential stuffing,
- SQL injection,
- XSS payload,
- HTTP flooding,
- suspicious traffic.

---

### Masalah 4 — Observability terfragmentasi

Log dan metrics berasal dari berbagai service sehingga sulit mengetahui:

```text
request masuk dari mana
request menuju service mana
berapa latency
service mana error
IP mana melakukan abuse
```

---

### Masalah 5 — Backend terekspos langsung

Jika service tersedia langsung melalui internet:

```text
Internet
   │
   ├── auth-service
   ├── user-service
   ├── payment-service
   └── order-service
```

attack surface menjadi lebih besar.

---

# 3. Proposed Solution

AegisGate menjadi **single entry point** untuk seluruh backend service.

```text
                       Internet

                           │
                           ▼

                  ┌─────────────────┐
                  │    AegisGate    │
                  │   API Gateway   │
                  └────────┬────────┘
                           │

       ┌───────────────────┼──────────────────┐
       │                   │                  │
       ▼                   ▼                  ▼

 Authentication      Rate Limiting       WAF Engine

       │                   │                  │
       └───────────────────┼──────────────────┘
                           │

                    Reverse Proxy

                           │

          ┌────────────────┼─────────────────┐
          │                │                 │
          ▼                ▼                 ▼

     Auth Service      User Service      Order Service
```

Semua request masuk melalui AegisGate.

AegisGate menentukan:

```text
Apakah client authenticated?

Apakah rate limit terlampaui?

Apakah request mengandung malicious payload?

Service mana yang harus menerima request?

Apakah backend service sehat?

Bagaimana request dicatat dan dimonitor?
```

---

# 4. Product Vision

AegisGate bertujuan menjadi:

> Lightweight cloud-native API Gateway dengan security detection dan observability yang dibangun menggunakan Go.

Project ini dirancang sebagai implementasi pembelajaran terhadap konsep yang digunakan pada sistem seperti:

- Kong,
- NGINX,
- Envoy,
- Cloudflare Gateway,
- AWS API Gateway,
- Traefik.

Namun AegisGate tidak bertujuan menggantikan produk tersebut.

Fokus AegisGate adalah:

```text
learning
+
engineering showcase
+
portfolio
```

---

# 5. Project Goals

## 5.1 Primary Goals

AegisGate harus mampu:

1. menerima HTTP request,
2. menentukan target backend,
3. meneruskan request menggunakan reverse proxy,
4. melakukan authentication,
5. melakukan distributed rate limiting,
6. mendeteksi malicious requests,
7. menghasilkan security events,
8. mencatat metrics dan traces,
9. mengirim real-time event ke dashboard,
10. berjalan melalui Docker,
11. mendukung horizontal scaling.

---

# 6. Non-Goals

Versi awal AegisGate tidak bertujuan untuk:

- menggantikan Kong / Envoy / NGINX,
- menjadi enterprise WAF penuh,
- melakukan deep packet inspection,
- menjadi SIEM penuh,
- menjadi IDS/IPS network layer,
- mendukung seluruh OAuth provider,
- mendukung seluruh protokol internet.

Protocol awal:

```text
HTTP
HTTPS
WebSocket
```

gRPC dapat ditambahkan pada fase selanjutnya.

---

# 7. Target Users

## Backend Developer

Menggunakan AegisGate untuk routing API dan authentication.

---

## DevOps Engineer

Menggunakan AegisGate untuk:

- traffic management,
- observability,
- deployment,
- service health.

---

## Security Engineer

Menggunakan AegisGate untuk:

- WAF rules,
- detection rules,
- security alerts,
- traffic analysis.

---

# 8. System Architecture

High-level architecture:

```text
                         CLIENT

                            │
                            ▼

                   ┌─────────────────┐
                   │   Load Balancer │
                   └────────┬────────┘
                            │
                            ▼

                   ┌─────────────────┐
                   │    AegisGate    │
                   │     Gateway     │
                   └────────┬────────┘

                            │

 ┌──────────────────────────┼──────────────────────────┐
 │                          │                          │
 ▼                          ▼                          ▼

Auth Middleware       Rate Limiter               WAF Engine

 │                          │                          │
 │                          ▼                          │
 │                        Redis                        │
 │                                                     │
 └──────────────────────────┼──────────────────────────┘

                            ▼

                    Routing Engine

                            │

                    Reverse Proxy

                            │

       ┌────────────────────┼─────────────────────┐
       │                    │                     │
       ▼                    ▼                     ▼

 Auth Service          User Service          Order Service

       │                    │                     │
       └────────────────────┼─────────────────────┘
                            │
                            ▼

                       PostgreSQL
```

---

# 9. Core Components

## 9.1 Gateway Server

Gateway Server merupakan entry point AegisGate.

Responsibilities:

- menerima HTTP request,
- menjalankan middleware pipeline,
- memilih target service,
- meneruskan request,
- menghasilkan response.

Possible Go packages:

```text
net/http
context
net/http/httputil
```

---

# 10. Middleware Pipeline

Request diproses secara berurutan:

```text
Incoming Request

        │

        ▼

Request ID Middleware

        │

        ▼

Logging Middleware

        │

        ▼

Authentication

        │

        ▼

Rate Limiter

        │

        ▼

WAF

        │

        ▼

Router

        │

        ▼

Reverse Proxy

        │

        ▼

Backend Service
```

---

# 11. Reverse Proxy Engine

Gateway harus dapat meneruskan traffic.

Contoh configuration:

```yaml
routes:
  - path: /api/users/*
    upstream: http://user-service:8080

  - path: /api/orders/*
    upstream: http://order-service:8080

  - path: /api/auth/*
    upstream: http://auth-service:8080
```

Example:

```text
GET

/api/users/10
```

AegisGate:

```text
/api/users/*
        ↓
user-service
        ↓
http://user-service:8080/users/10
```

---

# 12. Authentication

Authentication awal menggunakan JWT.

Flow:

```text
Login

   ↓

Auth Service

   ↓

JWT

   ↓

Client

   ↓

AegisGate

   ↓

Validate Token

   ↓

Backend
```

Token:

```json
{
  "user_id": "123",
  "role": "user",
  "exp": 1770000000
}
```

---

# 13. Authorization

AegisGate dapat mendukung Role-Based Access Control.

Contoh:

```text
ADMIN

/api/admin/*
```

Rule:

```yaml
authorization:
  - path: /api/admin/*
    roles:
      - admin
```

Jika role tidak sesuai:

```http
HTTP/1.1 403 Forbidden
```

---

# 14. Rate Limiting

Rate limiter digunakan untuk mencegah abuse.

Contoh:

```text
100 request / minute
per IP
```

Flow:

```text
Request

   ↓

IP

   ↓

Redis Counter

   ↓

Allowed?
```

Response:

```http
HTTP/1.1 429 Too Many Requests
```

Algorithms yang dapat diimplementasikan:

```text
Fixed Window

Sliding Window

Token Bucket
```

Default:

```text
Token Bucket
```

---

# 15. Distributed Rate Limiting

Ketika AegisGate memiliki beberapa instance:

```text
            Load Balancer

            /          \

       Gateway 1      Gateway 2

            \          /

               Redis
```

Redis digunakan sebagai shared state.

Dengan demikian rate limit tetap konsisten antar instance.

---

# 16. Web Application Firewall

WAF melakukan inspection terhadap:

```text
URL

query parameter

HTTP headers

request body
```

Initial detection:

### SQL Injection

Example:

```text
' OR 1=1 --
```

---

### XSS

Example:

```html
<script>
  alert(1);
</script>
```

---

### Path Traversal

Example:

```text
../../../etc/passwd
```

---

### Suspicious User Agent

Example:

```text
sqlmap
nikto
nmap
```

---

# 17. WAF Rule Engine

Rule configuration:

```yaml
rules:
  - id: SQLI-001
    name: Basic SQL Injection
    severity: high
    type: regex

  - id: XSS-001
    name: Script Injection
    severity: high
    type: regex
```

Rule action:

```text
ALLOW

LOG

BLOCK
```

---

# 18. Security Event Engine

Jika request mencurigakan:

```text
HTTP Request
      │
      ▼
WAF Detection
      │
      ▼
Security Event
```

Example event:

```json
{
  "event_id": "evt-28182",
  "timestamp": "2026-09-20T10:20:11Z",
  "source_ip": "103.24.10.2",
  "method": "POST",
  "path": "/api/login",
  "rule_id": "SQLI-001",
  "attack_type": "SQL_INJECTION",
  "severity": "HIGH",
  "action": "BLOCKED"
}
```

---

# 19. Detection Engine

Detection Engine menganalisis behavioural events.

Contoh rule:

```text
failed_login > 15

within 60 seconds
```

Result:

```text
Possible brute force
```

Another example:

```text
requests > 500

within 10 seconds
```

Result:

```text
Possible HTTP flood
```

---

# 20. Asynchronous Event Processing

Security processing tidak boleh memperlambat HTTP request.

Architecture:

```text
Request
   │
   ▼
Gateway
   │
   ├──────────────────────► Backend
   │
   ▼
Event Channel
   │
   ▼
Worker Pool
   │
   ▼
Detection Engine
```

Go implementation:

```text
goroutine
channel
worker pool
```

---

# 21. Worker Pool

Example:

```text
Event Channel

     │

 ┌───┼────┬────┐

 ▼   ▼    ▼    ▼

W1   W2   W3   W4
```

Workers dapat menangani:

- log processing,
- security detection,
- metrics aggregation,
- event broadcasting.

---

# 22. Event Queue

Initial version:

```text
Go Channel
```

Advanced version:

```text
NATS
```

Optional enterprise experiment:

```text
Kafka
```

---

# 23. Observability

AegisGate harus menyediakan tiga jenis telemetry:

```text
Metrics

Logs

Traces
```

---

# 24. Metrics

Metrics examples:

```text
aegis_requests_total

aegis_request_duration_seconds

aegis_blocked_requests_total

aegis_rate_limit_hits_total

aegis_backend_errors_total

aegis_active_connections
```

Metrics dapat diekspos melalui:

```text
/metrics
```

dan dikumpulkan oleh Prometheus.

---

# 25. Distributed Tracing

Trace example:

```text
Request

 │

 ├─ Gateway          3ms

 ├─ Auth             1ms

 ├─ Rate Limiter     2ms

 ├─ Redis            1ms

 └─ User Service    20ms

Total               27ms
```

Tracing menggunakan:

```text
OpenTelemetry
```

---

# 26. Logging

AegisGate menggunakan structured logging.

Example:

```json
{
  "timestamp": "2026-09-20T12:00:00Z",
  "level": "INFO",
  "request_id": "req-321",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "latency_ms": 12
}
```

---

# 27. Real-Time Dashboard

Admin dashboard menampilkan:

```text
requests per second

average latency

blocked requests

active clients

top attacking IP

attack types

backend service health

rate limit events
```

---

# 28. WebSocket Event Streaming

Security events dikirim secara realtime:

```text
Detection Engine

       ↓

Event Broadcaster

       ↓

WebSocket Server

       ↓

Dashboard
```

---

# 29. Service Health Monitoring

AegisGate melakukan health check:

```text
GET /health
```

Backend response:

```json
{
  "status": "healthy"
}
```

Gateway menyimpan kondisi:

```text
HEALTHY

DEGRADED

UNHEALTHY
```

---

# 30. Load Balancing

Jika service memiliki beberapa instance:

```text
user-service-1

user-service-2

user-service-3
```

AegisGate dapat menggunakan:

```text
Round Robin
```

Advanced:

```text
Least Connections
```

---

# 31. Circuit Breaker

Circuit breaker melindungi sistem ketika backend gagal.

State:

```text
CLOSED

OPEN

HALF OPEN
```

Example:

```text
5 consecutive failures

↓

OPEN
```

Requests sementara tidak diteruskan.

---

# 32. Retry Mechanism

Gateway dapat melakukan retry untuk request tertentu.

Example:

```text
Backend Timeout

       ↓

Retry

       ↓

Backend Replica
```

Maximum retry:

```text
2
```

Retry tidak dilakukan sembarangan pada operation non-idempotent.

---

# 33. Configuration Management

Configuration:

```text
config.yaml
```

Example:

```yaml
server:
  port: 8080

redis:
  host: redis
  port: 6379

security:
  rate_limit:
    requests: 100
    window: 60s
```

---

# 34. Database

PostgreSQL digunakan untuk persistent configuration.

Tables:

```text
users

api_keys

routes

security_rules

security_events

backend_services

audit_logs
```

---

# 35. Redis

Redis digunakan untuk:

```text
rate limiting

distributed counters

temporary cache

session data

security aggregation
```

---

# 36. API Key Management

Client dapat diberikan API key:

```text
X-API-Key
```

AegisGate melakukan:

```text
API Key

   ↓

Validation

   ↓

Rate Limit Policy

   ↓

Backend
```

---

# 37. Admin API

Control plane menyediakan API.

Example:

```text
POST

/api/v1/routes
```

```text
GET

/api/v1/security/events
```

```text
POST

/api/v1/security/rules
```

```text
GET

/api/v1/services
```

---

# 38. Control Plane vs Data Plane

Architecture dibagi menjadi dua.

## Data Plane

Menangani request.

```text
routing

proxy

rate limiting

security
```

---

## Control Plane

Mengatur gateway.

```text
route configuration

security policies

services

API keys

dashboard
```

Architecture:

```text
             Control Plane

                  │

                  ▼

               Config

                  │

                  ▼

Client → Data Plane → Backend
```

---

# 39. Proposed Repository Structure

```text
aegisgate/

├── cmd/
│
│   ├── gateway/
│   │   └── main.go
│
│   ├── controlplane/
│   │   └── main.go
│
│   └── worker/
│       └── main.go
│
├── internal/
│
│   ├── proxy/
│   ├── router/
│   ├── auth/
│   ├── ratelimiter/
│   ├── waf/
│   ├── detection/
│   ├── worker/
│   ├── event/
│   ├── telemetry/
│   ├── websocket/
│   └── config/
│
├── pkg/
│
│   ├── logger/
│   ├── middleware/
│   └── response/
│
├── services/
│
│   ├── auth-service/
│   ├── user-service/
│   └── order-service/
│
├── dashboard/
│
├── configs/
│
├── migrations/
│
├── deployments/
│
│   ├── docker/
│   ├── kubernetes/
│   └── terraform/
│
├── benchmarks/
│
├── tests/
│
├── docs/
│
│   ├── architecture.md
│   ├── security.md
│   ├── threat-model.md
│   └── benchmarks.md
│
├── docker-compose.yml
├── Makefile
├── go.mod
└── README.md
```

---

# 40. Technology Stack

## Backend

```text
Go
```

Possible framework:

```text
Chi
```

Namun core HTTP tetap memanfaatkan:

```text
net/http
```

agar project menunjukkan pemahaman fundamental Go networking.

---

## Database

```text
PostgreSQL
```

---

## Cache / Distributed State

```text
Redis
```

---

## Messaging

Initial:

```text
Go channels
```

Advanced:

```text
NATS
```

---

## Observability

```text
OpenTelemetry

Prometheus

Grafana
```

---

## Frontend

```text
Next.js

TypeScript

Tailwind CSS
```

---

## Infrastructure

```text
Docker

Docker Compose

Kubernetes

Terraform
```

---

## CI/CD

```text
GitHub Actions
```

---

# 41. Functional Requirements

AegisGate MUST:

- accept HTTP requests,
- route requests,
- proxy requests,
- validate authentication,
- apply rate limiting,
- inspect requests,
- generate security events,
- expose metrics,
- log requests,
- health-check backends.

AegisGate SHOULD:

- support WebSocket,
- provide dashboard,
- provide distributed tracing,
- support multiple gateway instances,
- support load balancing.

AegisGate MAY:

- support gRPC,
- support Kafka,
- support Kubernetes service discovery,
- support OAuth2,
- support external threat intelligence.

---

# 42. Non-Functional Requirements

## Performance

Target baseline:

```text
10,000+ requests/sec
```

during controlled benchmark.

Target akan disesuaikan dengan hardware.

---

## Latency

Gateway overhead target:

```text
P50 < 10ms

P95 < 30ms
```

excluding backend latency.

---

## Availability

Gateway harus dapat memiliki multiple instance.

```text
Gateway-1

Gateway-2

Gateway-3
```

---

## Scalability

Gateway harus stateless sebisa mungkin.

Shared state disimpan dalam:

```text
Redis

PostgreSQL
```

---

## Security

Gateway tidak boleh menyimpan:

```text
plaintext password

plaintext secret
```

Sensitive values menggunakan environment variables atau secrets.

---

# 43. Benchmark Strategy

Tools:

```text
k6

Vegeta

wrk
```

Test:

```text
100 users

500 users

1000 users

5000 users
```

Measure:

```text
requests/sec

P50 latency

P95 latency

P99 latency

CPU

RAM

error rate
```

---

# 44. Testing Strategy

## Unit Test

Target:

```text
router

rate limiter

WAF rules

authentication

detection engine
```

---

## Integration Test

Test:

```text
Gateway

Redis

PostgreSQL

Backend Services
```

---

## Load Test

Test high concurrency.

---

## Security Test

Simulate:

```text
SQL injection

XSS

brute force

API abuse

rate limit bypass
```

---

# 45. Security Threat Model

Threats:

```text
DDoS

brute force

credential stuffing

SQL injection

XSS

path traversal

API abuse

token theft

replay attack
```

Mitigation:

```text
rate limiting

authentication

WAF

logging

security detection

TLS
```

---

# 46. Deployment Architecture

Production-like environment:

```text
                    Internet

                       │

                       ▼

                  Load Balancer

                       │

          ┌────────────┼────────────┐

          ▼            ▼            ▼

       Gateway      Gateway      Gateway

          │            │            │

          └────────────┼────────────┘

                       │

             ┌─────────┴─────────┐

             ▼                   ▼

           Redis             PostgreSQL

                       │

                       ▼

               Backend Services
```

---

# 47. Docker Architecture

Development environment:

```text
docker-compose

├── gateway
├── control-plane
├── postgres
├── redis
├── prometheus
├── grafana
├── auth-service
├── user-service
└── order-service
```

---

# 48. Kubernetes Architecture

Future deployment:

```text
Namespace: aegisgate
```

Resources:

```text
Deployment

Service

ConfigMap

Secret

Ingress

HorizontalPodAutoscaler
```

---

# 49. CI/CD Pipeline

GitHub Actions:

```text
Push

  ↓

Lint

  ↓

Unit Test

  ↓

Integration Test

  ↓

Security Scan

  ↓

Docker Build

  ↓

Container Registry

  ↓

Deployment
```

---

# 50. Development Roadmap

## Phase 1 — Go Gateway Core

Implement:

```text
HTTP server

router

reverse proxy

middleware

logging
```

---

## Phase 2 — Authentication

Implement:

```text
JWT

API key

RBAC
```

---

## Phase 3 — Rate Limiting

Implement:

```text
Token Bucket

Redis
```

---

## Phase 4 — Security

Implement:

```text
WAF

security rules

event generation
```

---

## Phase 5 — Detection Engine

Implement:

```text
worker pool

security event pipeline

brute force detection

HTTP flood detection
```

---

## Phase 6 — Observability

Implement:

```text
Prometheus

OpenTelemetry

Grafana
```

---

## Phase 7 — Dashboard

Implement:

```text
Next.js dashboard

WebSocket

security analytics
```

---

## Phase 8 — Distributed System

Implement:

```text
multiple gateway instances

load balancing

circuit breaker

service health
```

---

## Phase 9 — Cloud Native

Implement:

```text
Docker

Kubernetes

Terraform

CI/CD
```

---

## Phase 10 — Engineering Evaluation

Perform:

```text
benchmark

profiling

security testing

chaos testing
```

---

# 51. Success Metrics

Project dianggap berhasil jika:

### Functional

```text
Gateway dapat memproxy request

JWT validation berjalan

Rate limiting berjalan

WAF dapat melakukan blocking

Security detection berjalan

Dashboard menerima realtime event
```

---

### Engineering

```text
unit test tersedia

integration test tersedia

benchmark terdokumentasi

Docker deployment berjalan

Kubernetes deployment berjalan

observability tersedia
```

---

### Portfolio

Repository harus memiliki:

```text
architecture diagram

demo video

benchmark result

threat model

API documentation

screenshots

technical decisions

deployment documentation
```

---

# 52. Engineering Decision Records

Repository harus memiliki:

```text
docs/adr/
```

ADR merupakan:

```text
Architecture Decision Record
```

Example:

```text
ADR-001 Why Go

ADR-002 Why Redis for Rate Limiting

ADR-003 Why NATS

ADR-004 Why Stateless Gateway

ADR-005 Why Worker Pool
```

Setiap decision menjelaskan:

```text
Context

Problem

Options

Decision

Consequences
```

---

# 53. Main Engineering Challenges

Project harus secara eksplisit mengeksplorasi:

### Go Concurrency

```text
goroutines

channels

mutex

worker pools

context cancellation
```

---

### Distributed Systems

```text
distributed state

load balancing

fault tolerance

retry

circuit breaker
```

---

### Networking

```text
HTTP

reverse proxy

connection handling

headers

timeouts
```

---

### Security

```text
authentication

authorization

WAF

rate limiting

detection engineering
```

---

### Observability

```text
logging

metrics

tracing
```

---

# 54. Portfolio Narrative

AegisGate sebaiknya tidak dipresentasikan sebagai:

> REST API built using Golang.

Tetapi:

> Designed and built a cloud-native API Gateway in Go featuring distributed rate limiting, reverse proxying, security detection, asynchronous event processing, Web Application Firewall capabilities, and full observability using OpenTelemetry and Prometheus.

Extended version:

> Built AegisGate, a distributed API Gateway and security platform written in Go. Implemented reverse proxy routing, JWT authentication, Redis-based distributed rate limiting, WAF rule processing, asynchronous detection pipelines using goroutines and worker pools, real-time security events, OpenTelemetry tracing, Prometheus metrics, Docker deployment, Kubernetes orchestration, and performance benchmarking.

---

# 55. Expected Learning Outcomes

Setelah menyelesaikan AegisGate, developer diharapkan memahami:

```text
Go networking

Go concurrency

HTTP internals

API Gateway architecture

distributed systems

Redis

PostgreSQL

security engineering

observability

Docker

Kubernetes

CI/CD

system design
```

---

# 56. Final Definition of AegisGate

AegisGate adalah:

> A cloud-native distributed API Gateway and security platform built in Go that provides reverse proxy routing, authentication, distributed rate limiting, Web Application Firewall capabilities, behavioral threat detection, observability, real-time security monitoring, and resilient backend traffic management.

Secara sederhana:

```text
AegisGate

=

API Gateway
+
Reverse Proxy
+
Rate Limiter
+
WAF
+
Detection Engine
+
Observability
+
Cloud-Native Infrastructure
```
