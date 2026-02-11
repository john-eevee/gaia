defmodule GaiaLib.Certs do
  @moduledoc """
  Mtls provides functionality to generate Root CA certificates, create CSRs,
  and sign certificates using Ed25519 keys via the x509 library.
  """

  alias GaiaLib.Certs.{CertificateAuthority, CSRCertificate, CertConfig, Error}

  @root_ca_validity_days 3650
  @key_curve :ed25519

  defmodule CertificateAuthority do
    @moduledoc """
    Represents a Certificate Authority (CA) with its certificate and private key.
     - `certificate`: PEM-encoded CA certificate
     - `private_key`: PEM-encoded private key corresponding to the CA certificate
    """
    @type t :: %__MODULE__{private_key: binary(), certificate: binary()}
    defstruct [:private_key, :certificate]

    defimpl Inspect do
      import Inspect.Algebra

      def inspect(%CertificateAuthority{} = ca, opts) do
        private_key = if ca.private_key, do: "[REDACTED]", else: "nil"
        certificate = if ca.certificate, do: "[REDACTED]", else: "nil"

        {concat([
           "CertificateAuthority<private_key: ",
           private_key,
           ", certificate: ",
           certificate,
           ">"
         ]), opts}
      end
    end
  end

  @doc """
  Validate that the given string is PEM armored.

  Accepts one or more PEM blocks (for example a cert chain or key + cert).
  Returns `:ok` when every PEM block decodes as base64, otherwise returns
  `{:error, reason}` describing the failure.
  """
  @spec validate_pem_armor(binary()) :: :ok | {:error, String.t()}
  def validate_pem_armor(pem) when is_binary(pem) do
    pem = String.trim(pem || "")

    cond do
      pem == "" ->
        {:error, "PEM string is empty"}

      true ->
        # Matches blocks like:
        # -----BEGIN TYPE-----\n(base64 or optional headers)\n-----END TYPE-----
        regex = ~r/-----BEGIN ([A-Za-z0-9 _-]+)-----(?:\r?\n)(.*?)(?:\r?\n)-----END \1-----/s

        case Regex.scan(regex, pem) do
          [] ->
            {:error, "Invalid PEM: no PEM armor found"}

          matches ->
            Enum.reduce_while(matches, :ok, fn
              [_, label, body], _acc ->
                # Remove header lines (e.g. "Proc-Type: 4,ENCRYPTED") and
                # join the remaining lines into a contiguous base64 string.
                base64 =
                  body
                  |> String.split(~r/\r?\n/)
                  |> Enum.reject(&String.contains?(&1, ":"))
                  |> Enum.join()
                  |> String.replace(~r/\s+/, "")

                case Base.decode64(base64) do
                  {:ok, decoded} when byte_size(decoded) > 0 ->
                    {:cont, :ok}

                  {:ok, _} ->
                    {:halt, {:error, "Invalid PEM: block #{label} decodes to empty binary"}}

                  :error ->
                    {:halt, {:error, "Invalid PEM: base64 decode failed for block #{label}"}}
                end
            end)
        end
    end
  end

  defmodule CertConfig do
    @moduledoc """
    Configuration for generating certificates and CSRs.
    """
    @type t :: %__MODULE__{
            organization: String.t(),
            organizational_unit: String.t(),
            country: String.t(),
            province: String.t(),
            locality: String.t(),
            street_address: String.t(),
            postal_code: String.t(),
            common_name: String.t()
          }
    defstruct [
      :organization,
      :organizational_unit,
      :country,
      :province,
      :locality,
      :street_address,
      :postal_code,
      :common_name
    ]

    def validate(config, :root_ca) do
      cond do
        is_nil(config.organization) or config.organization == "" ->
          {:error, "Config validation failed: Organization is required for Root CA"}

        is_nil(config.country) or config.country == "" ->
          {:error, "Config validation failed: Country is required for Root CA"}

        true ->
          :ok
      end
    end

    def validate(config, :csr) do
      no_common_name = is_nil(config.common_name) or config.common_name == ""
      no_organization = is_nil(config.organization) or config.organization == ""

      if no_common_name and no_organization do
        {:error, "Config validation failed: CSR requires either Common Name or Organization"}
      else
        :ok
      end
    end

    def to_rdn(config) do
      rnd_string =
        [
          {"O", config.organization},
          {"OU", config.organizational_unit},
          {"C", config.country},
          {"ST", config.province},
          {"L", config.locality},
          {"STREET", config.street_address},
          {"PC", config.postal_code},
          {"CN", config.common_name}
        ]
        |> Enum.filter(fn {_k, v} -> not is_nil(v) and v != "" end)
        |> Enum.map_join("/", fn {k, v} -> "#{k}=#{v}" end)

      "/" <> rnd_string
    end
  end

  defmodule CSRCertificate do
    @moduledoc """
    Represents a Certificate Signing Request (CSR) along with its associated key pair.
    """
    @type t :: %__MODULE__{csr: binary(), private_key: binary(), public_key: binary()}
    defstruct [:csr, :private_key, :public_key]

    defimpl Inspect do
      import Inspect.Algebra

      def inspect(%CSRCertificate{} = csr, opts) do
        private_key = if csr.private_key, do: "[REDACTED]", else: "nil"
        public_key = if csr.public_key, do: "[REDACTED]", else: "nil"
        csr_data = if csr.csr, do: "[REDACTED]", else: "nil"

        {concat([
           "CSRCertificate<csr: ",
           csr_data,
           ", private_key: ",
           private_key,
           ", public_key: ",
           public_key,
           ">"
         ]), opts}
      end
    end
  end

  defmodule Error do
    defexception [:message, :op, :err]

    @type t :: %__MODULE__{
            message: String.t(),
            op: atom(),
            err: any()
          }

    def message(%__MODULE__{message: msg, err: nil}), do: msg
    def message(%__MODULE__{message: msg, err: err}), do: "#{msg}: #{inspect(err)}"
  end

  def create_root_ca(config) do
    certificate = fn ->
      private_key = X509.PrivateKey.new_ec(@key_curve)
      public_key = X509.PublicKey.derive(private_key)
      rdn = CertConfig.to_rdn(config)
      serial = :crypto.strong_rand_bytes(16) |> :crypto.bytes_to_integer()
      validity = X509.Certificate.Validity.days_from_now(@root_ca_validity_days)

      certificate =
        X509.Certificate.self_signed(private_key, rdn,
          template: :root_ca,
          serial: serial,
          validity: validity
        )

      certificate_pem = X509.Certificate.to_pem(certificate)
      private_key_pem = X509.PrivateKey.to_pem(private_key)

      %CertificateAuthority{
        certificate: certificate_pem,
        private_key: private_key_pem
      }
    end

    with :ok <- CertConfig.validate(config, :root_ca) do
      {:ok, certificate.()}
    end
  end

  def create_csr(config) do
    csr = fn ->
      private_key = X509.PrivateKey.new_ec(@key_curve)
      rdn = CertConfig.to_rdn(config)
      csr = X509.CSR.new(private_key, rdn)
      csr_pem = X509.CSR.to_pem(csr)
      private_key_pem = X509.PrivateKey.to_pem(private_key)
      %CertificateAuthority{certificate: csr_pem, private_key: private_key_pem}
    end

    with :ok <- CertConfig.validate(config, :csr) do
      {:ok, csr.()}
    end
  end

  def sign_csr(csr_perm, certificate_authority, validity_days) do
  end
end
