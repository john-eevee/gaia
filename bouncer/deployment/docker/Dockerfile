# Build stage
FROM elixir:1.19-otp-28-alpine AS builder

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

# Compile and build release
RUN mix compile && \
    mix release

# Release stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache openssl ncurses-libs libstdc++ libgcc

WORKDIR /app

# Copy release from builder
COPY --from=builder /app/_build/prod/rel/bouncer ./

# Expose port
EXPOSE 4444

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:${BOUNCER_PORT:-4444}/health || exit 1

# Start the application
CMD ["/app/bin/bouncer", "start"]
