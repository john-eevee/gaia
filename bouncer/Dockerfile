# Build stage
FROM elixir:1.14-alpine AS builder

# Install build dependencies
RUN apk add --no-cache build-base git

WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Copy mix files
COPY mix.exs mix.lock ./

# Set build environment
ENV MIX_ENV=prod

# Install dependencies
RUN mix deps.get --only prod && \
    mix deps.compile

# Copy application code
COPY config ./config
COPY lib ./lib
COPY priv ./priv

# Compile the application
RUN mix compile

# Release stage
FROM elixir:1.14-alpine

# Install runtime dependencies
RUN apk add --no-cache openssl ncurses-libs libstdc++

WORKDIR /app

# Copy built application
COPY --from=builder /app/_build/prod /app/_build/prod
COPY --from=builder /app/config /app/config
COPY --from=builder /app/deps /app/deps

# Copy mix files for runtime
COPY mix.exs mix.lock ./

ENV MIX_ENV=prod

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:${BOUNCER_PORT:-4000}/health || exit 1

# Start the application
CMD ["mix", "run", "--no-halt"]
