defmodule GaiaLib.Certs do
  @moduledoc """
  Mtls provides functionality to generate Root CA certificates, create CSRs,
  and sign certificates using Ed25519 keys via the x509 library.
  """

  alias GaiaLib.Certs.{CertificateAuthority, CSRCertificate, CertConfig, Error}

  @root_ca_validity_days 3650

  defmodule CertificateAuthority do
    @moduledoc """
    Represents a Certificate Authority (CA) with its certificate and private key.
     - `certificate`: PEM-encoded CA certificate
     - `private_key`: PEM-encoded private key corresponding to the CA certificate
    """
    @type t :: %__MODULE__{
            private_key: binary(),
            certificate: binary()
          }
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

  # ============================================================================
  # Public API
  # ============================================================================

  @spec create_root_ca(CertConfig.t()) :: {:ok, CertificateAuthority.t()} | {:error, Error.t()}
  def create_root_ca(%CertConfig{} = config) do
    op = :create_root_ca

    with :ok <- CertConfig.validate(config, :root_ca),
         {:ok, priv_key_pem} <- generate_and_encode_ed25519_key(),
         {:ok, cert_pem} <-
           create_self_signed_cert(config, priv_key_pem, @root_ca_validity_days) do
      {:ok, %CertificateAuthority{certificate: cert_pem, private_key: priv_key_pem}}
    else
      {:error, reason} when is_binary(reason) ->
        {:error, %Error{message: reason, op: op}}

      error ->
        {:error, %Error{message: inspect(error), op: op, err: error}}
    end
  end

  @spec load_root_ca(binary(), binary()) ::
          {:ok, CertificateAuthority.t()} | {:error, Error.t()}
  def load_root_ca(ca_pem, key_pem) do
    op = :load_root_ca

    with :ok <- validate_pem_cert(ca_pem),
         :ok <- validate_pem_key(key_pem),
         :ok <- verify_key_matches_cert(ca_pem, key_pem) do
      {:ok, %CertificateAuthority{certificate: ca_pem, private_key: key_pem}}
    else
      {:error, reason} when is_binary(reason) ->
        {:error, %Error{message: reason, op: op}}

      error ->
        {:error, %Error{message: inspect(error), op: op, err: error}}
    end
  end

  @spec create_csr_certificate(CertConfig.t()) :: {:ok, CSRCertificate.t()} | {:error, Error.t()}
  def create_csr_certificate(%CertConfig{} = config) do
    op = :create_csr

    with :ok <- CertConfig.validate(config, :csr),
         {:ok, priv_key_pem} <- generate_and_encode_ed25519_key(),
         {:ok, csr_pem} <- create_csr(config, priv_key_pem),
         {:ok, pub_key_pem} <- extract_public_key(priv_key_pem) do
      {:ok, %CSRCertificate{csr: csr_pem, private_key: priv_key_pem, public_key: pub_key_pem}}
    else
      {:error, reason} when is_binary(reason) ->
        {:error, %Error{message: reason, op: op}}

      error ->
        {:error, %Error{message: inspect(error), op: op, err: error}}
    end
  end

  @spec sign_csr(CertificateAuthority.t(), binary(), integer()) ::
          {:ok, binary()} | {:error, Error.t()}
  def sign_csr(%CertificateAuthority{} = ca, csr_pem, validity_days) do
    op = :sign_csr

    with :ok <- validate_pem_csr(csr_pem),
         {:ok, cert_pem} <- sign_csr_with_openssl(ca, csr_pem, validity_days) do
      {:ok, cert_pem}
    else
      {:error, reason} when is_binary(reason) ->
        {:error, %Error{message: reason, op: op}}

      error ->
        {:error, %Error{message: inspect(error), op: op, err: error}}
    end
  end

  # ============================================================================
  # Internal Helpers - Key Generation
  # ============================================================================

  defp generate_and_encode_ed25519_key do
    try do
      # Generate Ed25519 key pair using the crypto module
      {_pub_key, priv_key} = :crypto.generate_key(:eddsa, :ed25519)

      # Create an EC private key record for Ed25519
      # The x509 library expects ec_private_key records with the ed25519 OID
      # OID for id-Ed25519
      oid_ed25519 = {1, 3, 101, 112}

      ec_key =
        {:ECPrivateKey, 1, priv_key, {:namedCurve, oid_ed25519}, :asn1_NOVALUE}

      # Convert to PEM - x509 will wrap it in PKCS#8 automatically for Ed25519
      priv_pem = X509.PrivateKey.to_pem(ec_key)
      {:ok, priv_pem}
    rescue
      e -> {:error, "failed to generate Ed25519 key: #{inspect(e)}"}
    end
  end

  defp create_self_signed_cert(config, priv_key_pem, validity_days) do
    try do
      private_key = X509.PrivateKey.from_pem!(priv_key_pem)
      subject_rdn = config_to_rdn(config)

      cert =
        X509.Certificate.self_signed(
          private_key,
          subject_rdn,
          template: :root_ca,
          validity: validity_days
        )

      cert_pem = X509.Certificate.to_pem(cert)
      {:ok, cert_pem}
    rescue
      e -> {:error, "failed to create self-signed certificate: #{inspect(e)}"}
    end
  end

  defp create_csr(config, priv_key_pem) do
    try do
      private_key = X509.PrivateKey.from_pem!(priv_key_pem)
      subject_rdn = config_to_rdn(config)

      csr = X509.CSR.new(private_key, subject_rdn)
      csr_pem = X509.CSR.to_pem(csr)
      {:ok, csr_pem}
    rescue
      e -> {:error, "failed to create CSR: #{inspect(e)}"}
    end
  end

  defp sign_csr_with_openssl(%CertificateAuthority{} = ca, csr_pem, validity_days) do
    try do
      ca_key = X509.PrivateKey.from_pem!(ca.private_key)
      ca_cert = X509.Certificate.from_pem!(ca.certificate)
      csr = X509.CSR.from_pem!(csr_pem)

      cert =
        csr
        |> X509.CSR.public_key()
        |> X509.Certificate.new(
          X509.CSR.subject(csr),
          ca_cert,
          ca_key,
          validity: validity_days
        )

      cert_pem = X509.Certificate.to_pem(cert)
      {:ok, cert_pem}
    rescue
      e -> {:error, "failed to sign CSR: #{inspect(e)}"}
    end
  end

  defp extract_public_key(priv_key_pem) do
    try do
      private_key = X509.PrivateKey.from_pem!(priv_key_pem)
      public_key = X509.PublicKey.derive(private_key)
      pub_pem = X509.PublicKey.to_pem(public_key)
      {:ok, pub_pem}
    rescue
      e -> {:error, "failed to extract public key: #{inspect(e)}"}
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  # ============================================================================
  # DN Handling
  # ============================================================================

  defp config_to_rdn(config) do
    # Build a name string compatible with x509
    # Format: "/C=.../ST=.../L=.../O=.../OU=.../STREET=.../postalCode=.../CN=..."
    parts = []

    parts = if config.country, do: parts ++ ["C=#{config.country}"], else: parts
    parts = if config.province, do: parts ++ ["ST=#{config.province}"], else: parts
    parts = if config.locality, do: parts ++ ["L=#{config.locality}"], else: parts
    parts = if config.organization, do: parts ++ ["O=#{config.organization}"], else: parts

    parts =
      if config.organizational_unit,
        do: parts ++ ["OU=#{config.organizational_unit}"],
        else: parts

    parts =
      if config.street_address, do: parts ++ ["STREET=#{config.street_address}"], else: parts

    parts = if config.postal_code, do: parts ++ ["postalCode=#{config.postal_code}"], else: parts
    parts = if config.common_name, do: parts ++ ["CN=#{config.common_name}"], else: parts

    "/" <> Enum.join(parts, "/")
  end

  # ============================================================================
  # Validation Helpers
  # ============================================================================

  defp verify_key_matches_cert(cert_pem, key_pem) do
    try do
      private_key = X509.PrivateKey.from_pem!(key_pem)
      cert = X509.Certificate.from_pem!(cert_pem)

      pub_key_from_key = X509.PublicKey.derive(private_key)
      pub_key_from_cert = X509.Certificate.public_key(cert)

      # Compare the DER-encoded representations
      if X509.PublicKey.to_der(pub_key_from_key) == X509.PublicKey.to_der(pub_key_from_cert) do
        :ok
      else
        {:error, "private key does not match certificate"}
      end
    rescue
      e -> {:error, "failed to verify key matches cert: #{inspect(e)}"}
    end
  end

  defp validate_pem_cert(pem) when is_binary(pem) do
    if String.contains?(pem, "-----BEGIN CERTIFICATE-----") and
         String.contains?(pem, "-----END CERTIFICATE-----") do
      :ok
    else
      {:error, "invalid certificate PEM format"}
    end
  end

  defp validate_pem_csr(pem) when is_binary(pem) do
    if String.contains?(pem, "-----BEGIN CERTIFICATE REQUEST-----") and
         String.contains?(pem, "-----END CERTIFICATE REQUEST-----") do
      :ok
    else
      {:error, "invalid CSR PEM format"}
    end
  end

  defp validate_pem_key(pem) when is_binary(pem) do
    if String.contains?(pem, "-----BEGIN PRIVATE KEY-----") and
         String.contains?(pem, "-----END PRIVATE KEY-----") do
      :ok
    else
      {:error, "invalid private key PEM format"}
    end
  end
end
