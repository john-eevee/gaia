defmodule Gaia.Bouncer.Router do
  @moduledoc """
  HTTP Router for the Bouncer OCSP-like server.

  Handles certificate validation requests from the reverse proxy.
  Returns 200 for valid certificates, 412 for revoked/invalid certificates.
  """

  use Plug.Router
  require Logger

  plug(:match)
  plug(:dispatch)

  # Health check endpoint
  get "/health" do
    send_resp(conn, 200, "OK")
  end

  # Certificate validation endpoint
  # Expects client certificate to be passed in the request headers
  post "/validate" do
    start_time = System.monotonic_time()

    result =
      with {:ok, cert_pem} <- extract_certificate(conn),
           {:ok, serial} <- Gaia.Bouncer.Certificate.parse_serial(cert_pem),
           {:ok, status} <- Gaia.Bouncer.Database.check_certificate_status(serial) do
        case status do
          :valid -> {:ok, 200}
          :revoked -> {:ok, 412}
          :unknown -> {:ok, 412}
        end
      else
        {:error, reason} ->
          Logger.warning("Certificate validation failed: #{inspect(reason)}")
          {:error, 412}
      end

    duration = System.monotonic_time() - start_time

    case result do
      {:ok, status_code} ->
        :telemetry.execute(
          [:bouncer, :request, :success],
          %{duration: duration},
          %{status: status_code}
        )

        send_resp(conn, status_code, "")

      {:error, status_code} ->
        :telemetry.execute(
          [:bouncer, :request, :failure],
          %{duration: duration},
          %{}
        )

        send_resp(conn, status_code, "")
    end
  end

  # Fallback for unmatched routes
  match _ do
    send_resp(conn, 404, "Not Found")
  end

  # Extract certificate from request headers
  defp extract_certificate(conn) do
    case get_req_header(conn, "x-client-cert") do
      [cert_pem | _] when is_binary(cert_pem) and byte_size(cert_pem) > 0 ->
        {:ok, cert_pem}

      _ ->
        {:error, :missing_certificate}
    end
  end
end
