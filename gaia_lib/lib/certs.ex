defmodule GaiaLib.Certs do
  @moduledoc """
  Mtls provides functionality to generate Root CA certificates, create CSRs,
  and sign certificates using Ed25519 keys via the x509 library.
  """

  alias GaiaLib.Certs.{
    CertificatePair,
    CSRCertificate,
    CertConfig,
    ConfigValidationError,
    PEMError
  }

  @root_ca_validity_days 3650
  @key_curve :ed25519

  defmodule CertificatePair do
    @moduledoc """
    Represents a Certificate Authority (CA) with its certificate and private key.
     - `certificate`: PEM-encoded CA certificate
     - `private_key`: PEM-encoded private key corresponding to the CA certificate
    """
    @type t :: %__MODULE__{private_key: binary(), certificate: binary()}
    defstruct [:private_key, :certificate]

    defimpl Inspect do
      import Inspect.Algebra

      def inspect(%CertificatePair{} = ca, opts) do
        private_key = if ca.private_key, do: "[REDACTED]", else: "nil"
        certificate = if ca.certificate, do: "[REDACTED]", else: "nil"

        {concat([
           "CertificatePair<private_key: ",
           private_key,
           ", certificate: ",
           certificate,
           ">"
         ]), opts}
      end
    end
  end

  defmodule ConfigValidationError do
    @moduledoc """
    raised when a certificate configuration fails validation.
    Fields:
      - `message`: human readable description
      - `field`: the field that failed validation (if known)
    """
    defexception [:message, :field, :op]

    @type t :: %__MODULE__{message: String.t(), field: atom() | nil}

    def message(%__MODULE__{message: msg}), do: msg
  end

  defmodule PEMError do
    @moduledoc """
    related to PEM parsing/decoding.
    Fields:
      - `message`: human readable description
      - `label`: optional PEM block label (e.g. CERTIFICATE)
      - `reason`: internal atom describing the failure
    """
    defexception [:message, :label, :reason]

    @type t :: %__MODULE__{message: String.t(), label: String.t() | nil, reason: atom() | any()}

    def message(%__MODULE__{message: msg}), do: msg
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

    def validate(config, type = :root_ca) do
      cond do
        is_nil(config.organization) or config.organization == "" ->
          {:error,
           %ConfigValidationError{
             message: "Config validation failed: Organization is required for Root CA",
             field: :organization,
             op: type
           }}

        is_nil(config.country) or config.country == "" ->
          {:error,
           %ConfigValidationError{
             message: "Config validation failed: Country is required for Root CA",
             field: :country,
             op: type
           }}

        true ->
          :ok
      end
    end

    def validate(config, type = :csr) do
      no_common_name = is_nil(config.common_name) or config.common_name == ""
      no_organization = is_nil(config.organization) or config.organization == ""

      if no_common_name and no_organization do
        {:error,
         %ConfigValidationError{
           message: "Config validation failed: CSR requires either Common Name or Organization",
           field: nil,
           op: type
         }}
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

  def create_root_ca(config) do
    certificate = fn ->
      private_key = X509.PrivateKey.new_ec(@key_curve)
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

      %CertificatePair{
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
      %CertificatePair{certificate: csr_pem, private_key: private_key_pem}
    end

    with :ok <- CertConfig.validate(config, :csr) do
      {:ok, csr.()}
    end
  end

  def sign_csr(csr_perm, root_ca, validity_days) do
  end

  @doc """
  Validate that the given string is PEM armored.

  Accepts one or more PEM blocks (for example a cert chain or key + cert).
  Returns `:ok` when every PEM block decodes as base64, otherwise returns
  `{:error, reason}` describing the failure.
  """
  @spec validate_pem_armor(binary()) :: :ok | {:error, t()}
  def validate_pem_armor(pem) do
    pem
    |> String.trim()
    |> do_validate_pem_armor()
  end

  defp do_validate_pem_armor("") do
    {:error, %PEMError{message: "PEM is empty", reason: :empty}}
  end

  defp do_validate_pem_armor(pem) when is_binary(pem) do
    # Matches blocks like:
    # -----BEGIN TYPE-----\n(base64 or optional headers)\n-----END TYPE-----
    regex = ~r/-----BEGIN ([A-Za-z0-9 _-]+)-----(?:\r?\n)(.*?)(?:\r?\n)-----END \1-----/s

    case Regex.scan(regex, pem) do
      [] ->
        {:error, %PEMError{message: "Invalid PEM: no PEM armor found", reason: :no_armor}}

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
                {:halt,
                 {:error,
                  %PEMError{
                    message: "Invalid PEM: block #{label} decodes to empty binary",
                    label: label,
                    reason: :empty_decoded
                  }}}

              :error ->
                {:halt,
                 {:error,
                  %PEMError{
                    message: "Invalid PEM: base64 decode failed for block #{label}",
                    label: label,
                    reason: :base64_decode_failed
                  }}}
            end
        end)
    end
  end
end
