defmodule Gaia.Bouncer do
  @moduledoc """
  Gaia Bouncer - OCSP-like Certificate Validation Server

  A lightweight, high-availability server that validates certificate status
  for reverse proxy authentication. Built with Elixir, Plug, and Postgrex.

  ## Features

  - Fast certificate serial extraction and validation
  - Database-backed status checking with read-only access
  - Telemetry for request processing time and failure tracking
  - HTTP endpoints returning 200 (valid) or 412 (revoked/invalid)

  ## Usage

  The server exposes two main endpoints:

  - `GET /health` - Health check endpoint
  - `POST /validate` - Certificate validation endpoint (expects X-Client-Cert header)

  """
end
