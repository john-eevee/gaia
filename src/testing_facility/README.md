## TestingFacility

TestingFacility is a lightweight shared testing library for the broader Gaia
project. It collects helpers, shared cases, and fixtures so that Gaia services can
reuse consistent test patterns (certificate handling, security expectations, etc.)
across repositories without duplicating setup logic.

## Purpose

- **Shared fixtures** for common security-related components (certificates, identity,
  and transport configuration).
- **Support modules** that wrap third-party dependencies so every repo can depend
  on a single, versioned helper instead of chasing ad-hoc copies.
- **Documentation** that describes how Gaia services should bootstrap and assert
  security properties in their test suites.

## Usage within Gaia

Add this library as a dependency for any Gaia repo that needs the shared test behavior:
```elixir
def deps do
  [
    {:testing_facility, path: "../testing_facility", only: :test}
  ]
end
```

If/when the project is published to Hex, replace the `:path` option with the
published version constraint (e.g., `{:testing_facility, "~> 0.1"}`).

Expose the shared helpers via `use TestingFacility.CertificateCase` or other
modules defined here.

## Testing this library

```
mix test
```

Run tests in this library as well as downstream services that import it so you can
ensure compatibility when updating shared fixtures or utilities.
