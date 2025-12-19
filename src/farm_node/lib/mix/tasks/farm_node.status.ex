defmodule Mix.Tasks.FarmNode.Status do
  @shortdoc "Check the provisioning status of the Farm Node"

  @moduledoc """
  Displays the current provisioning status of the Farm Node.

  This task shows:
  - Whether the node is provisioned
  - Certificate details (if provisioned)
  - Credential file locations

  ## Usage

      mix farm_node.status
  """

  use Mix.Task

  alias Gaia.FarmNode.HubConnection.Provisioning
  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  @requirements ["app.config"]

  @impl Mix.Task
  def run(_args) do
    {:ok, _} = Application.ensure_all_started(:farm_node)

    Mix.shell().info("""

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    🔍 Farm Node Status
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)

    status = Provisioning.status()

    case status do
      :unprovisioned ->
        Mix.shell().info("""
        Status: ⚠️  UNPROVISIONED

        This node has not been provisioned with the Hub yet.

        To provision this node, run:
          mix farm_node.provision
        """)

      :active ->
        display_active_status()
    end

    Mix.shell().info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
  end

  defp display_active_status do
    case Storage.get_credential_paths() do
      {:ok, paths} ->
        cert_info = get_certificate_info(paths.cert)

        Mix.shell().info("""
        Status: ✅ ACTIVE

        Credentials Location:
          Certificate: #{paths.cert}
          Private Key: #{paths.key}

        #{cert_info}

        The node is ready to communicate with the Hub.
        """)

      {:error, _} ->
        Mix.shell().error("""
        Status: ❌ ERROR

        The node appears to be provisioned but credentials cannot be loaded.
        This may indicate a permissions or file system issue.
        """)
    end
  end

  defp get_certificate_info(cert_path) do
    case File.read(cert_path) do
      {:ok, pem} ->
        parse_certificate_details(pem)

      {:error, _} ->
        "Unable to read certificate details"
    end
  end

  defp parse_certificate_details(pem) do
    try do
      [{:Certificate, der, _}] = :public_key.pem_decode(pem)
      cert = :public_key.pkix_decode_cert(der, :otp)

      subject = extract_subject(cert)
      {not_before, not_after} = extract_validity(cert)

      """
      Certificate Details:
        Subject: #{subject}
        Valid From: #{not_before}
        Valid Until: #{not_after}
      """
    rescue
      _ -> "Unable to parse certificate details"
    end
  end

  defp extract_subject(cert) do
    {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, subject, _, _, _, _, _}, _, _} = cert
    {:rdnSequence, rdns} = subject

    rdns
    |> List.flatten()
    |> Enum.map(fn {:AttributeTypeAndValue, _oid, value} ->
      case value do
        {:utf8String, str} -> str
        {:printableString, str} -> to_string(str)
        _ -> inspect(value)
      end
    end)
    |> Enum.join(", ")
  end

  defp extract_validity(cert) do
    {:OTPCertificate,
     {:OTPTBSCertificate, _, _, _, _, _, {:Validity, not_before, not_after}, _, _, _, _}, _, _} =
      cert

    {format_time(not_before), format_time(not_after)}
  end

  defp format_time({:utcTime, time}) do
    to_string(time)
  end

  defp format_time({:generalTime, time}) do
    to_string(time)
  end
end
