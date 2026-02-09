defmodule GaiaLib.MTls do
  @moduledoc """
  Mtls provides functionality to generate Root CA certificates, create CSRs,
  and sign certificates using Ed25519 keys via OpenSSL.
  """

  alias GaiaLib.MTls.{CertificateAuthority, CSRCertificate, Config, Error}

  @root_ca_validity_years 10

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

  defmodule Config do
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

  @spec create_root_ca(Config.t()) :: {:ok, CertificateAuthority.t()} | {:error, Error.t()}
  def create_root_ca(%Config{} = config) do
    op = :create_root_ca

    with :ok <- Config.validate(config, :root_ca),
         {:ok, priv_key_pem} <- generate_and_encode_ed25519_key(),
         {:ok, cert_pem} <-
           create_self_signed_cert(config, priv_key_pem, @root_ca_validity_years * 365) do
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

  @spec create_csr_certificate(Config.t()) :: {:ok, CSRCertificate.t()} | {:error, Error.t()}
  def create_csr_certificate(%Config{} = config) do
    op = :create_csr

    with :ok <- Config.validate(config, :csr),
         {:ok, priv_key_pem} <- generate_and_encode_ed25519_key(),
         {:ok, csr_pem} <- create_csr_with_openssl(config, priv_key_pem),
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
      # Generate Ed25519 key pair using crypto module
      {_pub_key, priv_key} = :crypto.generate_key(:eddsa, :ed25519)

      # Create a temporary directory
      temp_dir = Path.join(System.tmp_dir!(), "gaia_mtls_#{:erlang.unique_integer()}")
      File.mkdir_p!(temp_dir)

      try do
        # Create PKCS8 PEM manually from the raw 32-byte key
        # PKCS8 structure for Ed25519: 
        # The raw key is wrapped in an OCTET STRING inside PrivateKeyInfo
        pkcs8_pem = encode_ed25519_pkcs8(priv_key)
        {:ok, pkcs8_pem}
      after
        File.rm_rf!(temp_dir)
      end
    rescue
      e -> {:error, "failed to generate Ed25519 key: #{inspect(e)}"}
    end
  end

  defp encode_ed25519_pkcs8(priv_key) when is_binary(priv_key) and byte_size(priv_key) == 32 do
    # PKCS#8 structure for Ed25519
    # PrivateKeyInfo ::= SEQUENCE {
    #   version INTEGER,
    #   privateKeyAlgorithm AlgorithmIdentifier,
    #   privateKey OCTET STRING,
    #   ...
    # }

    # Build DER manually
    # OID for Ed25519
    oid_ed25519 = <<0x06, 0x03, 0x2B, 0x65, 0x70>>
    # INTEGER 0
    version = <<0x02, 0x01, 0x00>>

    # AlgorithmIdentifier SEQUENCE - includes OID tag and length bytes
    algo_id = <<0x30, 0x05>> <> oid_ed25519

    # OCTET STRING containing the private key
    # First layer: wrap raw key in OCTET STRING (0x04 0x20)
    inner_octets = <<0x04, 0x20>> <> priv_key
    # Second layer: wrap the inner OCTET STRING in an OCTET STRING for PrivateKey
    priv_key_octets = <<0x04, byte_size(inner_octets)>> <> inner_octets

    # Full PrivateKeyInfo SEQUENCE
    pkcs8_content = version <> algo_id <> priv_key_octets
    pkcs8_length = byte_size(pkcs8_content)

    pkcs8_der =
      if pkcs8_length < 128 do
        <<0x30, pkcs8_length>> <> pkcs8_content
      else
        len_bytes = :binary.encode_unsigned(pkcs8_length)
        <<0x30, 0x81, len_bytes::binary>> <> pkcs8_content
      end

    # Encode to PEM
    der_to_pem(pkcs8_der, "PRIVATE KEY")
  end

  defp der_to_pem(der, label) when is_binary(der) do
    encoded = Base.encode64(der, padding: true)

    lines =
      encoded
      |> String.split("", trim: true)
      |> Enum.chunk_every(64)
      |> Enum.map_join("\n", &Enum.join/1)

    "-----BEGIN #{label}-----\n#{lines}\n-----END #{label}-----\n"
  end

  defp create_self_signed_cert(config, priv_key_pem, validity_days) do
    try do
      # Build subject DN string
      subject_dn = config_to_subject_string(config)

      # Create temporary files
      key_file = Path.join(System.tmp_dir!(), "ca_key_#{:erlang.unique_integer()}.pem")
      cert_file = Path.join(System.tmp_dir!(), "ca_cert_#{:erlang.unique_integer()}.pem")

      try do
        # Write key to temp file
        File.write!(key_file, priv_key_pem)

        # Use OpenSSL to create self-signed certificate
        result =
          System.cmd("openssl", [
            "req",
            "-new",
            "-x509",
            "-days",
            Integer.to_string(validity_days),
            "-key",
            key_file,
            "-out",
            cert_file,
            "-subj",
            subject_dn
          ])

        case result do
          {_, 0} ->
            cert_pem = File.read!(cert_file)
            {:ok, cert_pem}

          {error_msg, code} ->
            {:error, "OpenSSL req failed (code #{code}): #{error_msg}"}
        end
      after
        safe_rm(key_file)
        safe_rm(cert_file)
      end
    rescue
      e -> {:error, "failed to create self-signed certificate: #{inspect(e)}"}
    end
  end

  defp create_csr_with_openssl(config, priv_key_pem) do
    try do
      subject_dn = config_to_subject_string(config)

      key_file = Path.join(System.tmp_dir!(), "csr_key_#{:erlang.unique_integer()}.pem")
      csr_file = Path.join(System.tmp_dir!(), "csr_#{:erlang.unique_integer()}.pem")

      try do
        File.write!(key_file, priv_key_pem)

        result =
          System.cmd("openssl", [
            "req",
            "-new",
            "-key",
            key_file,
            "-out",
            csr_file,
            "-subj",
            subject_dn
          ])

        case result do
          {_, 0} ->
            csr_pem = File.read!(csr_file)
            {:ok, csr_pem}

          {error_msg, code} ->
            {:error, "OpenSSL req failed (code #{code}): #{error_msg}"}
        end
      after
        safe_rm(key_file)
        safe_rm(csr_file)
      end
    rescue
      e -> {:error, "failed to create CSR: #{inspect(e)}"}
    end
  end

  defp sign_csr_with_openssl(%CertificateAuthority{} = ca, csr_pem, validity_days) do
    try do
      ca_key_file = Path.join(System.tmp_dir!(), "ca_key_sign_#{:erlang.unique_integer()}.pem")
      ca_cert_file = Path.join(System.tmp_dir!(), "ca_cert_sign_#{:erlang.unique_integer()}.pem")
      csr_input_file = Path.join(System.tmp_dir!(), "csr_input_#{:erlang.unique_integer()}.pem")

      cert_output_file =
        Path.join(System.tmp_dir!(), "cert_output_#{:erlang.unique_integer()}.pem")

      try do
        File.write!(ca_key_file, ca.private_key)
        File.write!(ca_cert_file, ca.certificate)
        File.write!(csr_input_file, csr_pem)

        result =
          System.cmd("openssl", [
            "x509",
            "-req",
            "-in",
            csr_input_file,
            "-CA",
            ca_cert_file,
            "-CAkey",
            ca_key_file,
            "-CAcreateserial",
            "-out",
            cert_output_file,
            "-days",
            Integer.to_string(validity_days)
          ])

        case result do
          {_, 0} ->
            cert_pem = File.read!(cert_output_file)
            {:ok, cert_pem}

          {error_msg, code} ->
            {:error, "OpenSSL x509 failed (code #{code}): #{error_msg}"}
        end
      after
        safe_rm(ca_key_file)
        safe_rm(ca_cert_file)
        safe_rm(csr_input_file)
        safe_rm(cert_output_file)
        # Clean up the serial file that OpenSSL creates
        safe_rm(ca_cert_file <> ".srl")
      end
    rescue
      e -> {:error, "failed to sign CSR: #{inspect(e)}"}
    end
  end

  defp extract_public_key(priv_key_pem) do
    try do
      key_file = Path.join(System.tmp_dir!(), "priv_key_#{:erlang.unique_integer()}.pem")
      pub_file = Path.join(System.tmp_dir!(), "pub_key_#{:erlang.unique_integer()}.pem")

      try do
        File.write!(key_file, priv_key_pem)

        result =
          System.cmd("openssl", [
            "pkey",
            "-in",
            key_file,
            "-pubout",
            "-out",
            pub_file
          ])

        case result do
          {_, 0} ->
            pub_pem = File.read!(pub_file)
            {:ok, pub_pem}

          {error_msg, code} ->
            {:error, "OpenSSL pkey failed (code #{code}): #{error_msg}"}
        end
      after
        safe_rm(key_file)
        safe_rm(pub_file)
      end
    rescue
      e -> {:error, "failed to extract public key: #{inspect(e)}"}
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp safe_rm(file_path) do
    File.rm(file_path)
  rescue
    _ -> :ok
  end

  # ============================================================================
  # DN Handling
  # ============================================================================

  defp config_to_subject_string(config) do
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
    with {:ok, pub_key_from_key} <- extract_public_key(key_pem),
         {:ok, pub_key_from_cert} <- extract_public_key_from_cert(cert_pem) do
      if pub_key_from_key == pub_key_from_cert do
        :ok
      else
        {:error, "private key does not match certificate"}
      end
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp extract_public_key_from_cert(cert_pem) when is_binary(cert_pem) do
    pub_file = Path.join(System.tmp_dir!(), "pub_key_from_cert_#{:erlang.unique_integer()}.pem")
    cert_file = Path.join(System.tmp_dir!(), "ca_cert_#{:erlang.unique_integer()}.pem")

    try do
      File.write!(cert_file, cert_pem)

      result =
        System.cmd("openssl", [
          "x509",
          "-in",
          cert_file,
          "-pubkey",
          "-noout",
          "-out",
          pub_file
        ])

      case result do
        {_, 0} ->
          pub_pem = File.read!(pub_file)
          {:ok, pub_pem}

        {error_msg, code} ->
          {:error, "OpenSSL failed to extract public key from cert (code #{code}): #{error_msg}"}
      end
    rescue
      e -> {:error, "failed to extract public key from certificate: #{inspect(e)}"}
    after
      safe_rm(cert_file)
      safe_rm(pub_file)
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
