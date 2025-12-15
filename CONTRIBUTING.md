# Contributing to Gaia

Thank you for your interest in contributing to Gaia! We welcome contributions from farm partners, developers, and the broader community.

## How to Contribute

### Code Quality Standards

All contributions must meet the following standards:

- **Code Analysis**: Code must pass Credo analysis
- **Testing**: Include tests for all new features and bug fixes
- **Formatting**: Format you code.
- **Dependency Security**: Run security dependency audits if added any
 dependency before

Run the following command to execute all checks
 ```bash
 mix ci
 ```

### Architecture Guidelines

- Respect **DDD (Domain-Driven Design)** principles and bounded contexts
- Keep contexts (Farm Management, Device Management, Local Rules) separate and focused
- Maintain clear public interfaces for each context
- Hide internal implementation details

### Submission Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes with tests
4. Ensure all checks pass
5. Commit with clear messages, following [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/#summary)
6. Push to your fork
7. Submit a pull request with a description of your changes

### Reporting Issues

- Describe the problem clearly
- Include steps to reproduce (if applicable)
- Specify your environment (Elixir version, OS, etc.)
- Attach relevant logs or error messages

## Development Setup

A [mise](https://mise.jdx.dev/) file is provided [here](./mise.toml) to ensure proper versions. You are
free to install them using other means. For convenience and repeatable builds, mise
is recommended.


```bash
# Clone the repository
git clone <repository-url>
cd gaia

# Install tools
mise install

# Go to the application will want to contribute
cd src/hub

# Get dependencies and compile
mix do deps.get, compile

# Use mix to check other tasks
mix help
```

## Logging Best Practices

- **Use structured metadata:** Prefer `Logger.metadata/1` to attach context like `farm_id`, `farmer_id`, `resource`, or `port` to logs rather than interpolating these values into the message.
- **Keep messages concise:** Log messages should describe the event (e.g. "Registered new farmer") while metadata carries the contextual details.
- **Clear metadata when done:** Call `Logger.metadata([])` after logging if the metadata should not persist for subsequent calls in the same process.

Example:

```elixir
Logger.metadata(farm_id: farm.id, farmer_id: farmer.id)
Logger.info("Registered new farmer")
Logger.metadata([])
```

**Thank you.**
