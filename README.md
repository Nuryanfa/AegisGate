# AegisGate

AegisGate is a portfolio-grade, cloud-native API gateway and security platform
built primarily in Go.

The project explores reverse proxying, authentication and authorization,
distributed rate limiting, request inspection, asynchronous security-event
processing, observability, and resilient backend traffic management.

> Status: planning and initial repository setup. See [PRD.md](PRD.md) for the
> product vision.

## Planned first milestone

- HTTP gateway built on Go's `net/http`
- Deterministic route matching and reverse proxying
- Structured request logging and request IDs
- Explicit server and upstream timeouts
- Health and readiness endpoints
- Graceful shutdown
- Unit and integration tests
- Docker Compose demo and reproducible baseline benchmark

## License

No license has been selected yet. Until a license is added, all rights are
reserved by the repository owner.
