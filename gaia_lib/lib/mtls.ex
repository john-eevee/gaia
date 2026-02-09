defmodule GaiaLib.MTls do
  @moduledoc """
  Mtls provides functionality to generate Root CA certificates, create CSRs,
  and sign certificates using Ed25519 keys.
  """

  require Record

  # Load Erlang Records for X.509 manipulation
  # These are standard records defined in the Erlang public_key application
  Record.defrecordp(
    :otp_cert,
    :OTPCertificate,
    extract(:OTPCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :tbs_cert,
    :OTPTBSCertificate,
    extract(:OTPTBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :cert_req,
    :CertificationRequest,
    extract(:CertificationRequest, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :cert_req_info,
    :CertificationRequestInfo,
    extract(:CertificationRequestInfo, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :attribute,
    :Attribute,
    extract(:Attribute, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :algo_id,
    :AlgorithmIdentifier,
    extract(:AlgorithmIdentifier, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :extension,
    :Extension,
    extract(:Extension, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :validity,
    :Validity,
    extract(:Validity, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :spki,
    :SubjectPublicKeyInfo,
    extract(:SubjectPublicKeyInfo, from_lib: "public_key/include/public_key.hrl")
  )

  # OIDs
  @oid_ed25519 {1, 3, 101, 112}
  @oid_basic_constraints {2, 5, 29, 19}
  @oid_key_usage {2, 5, 29, 15}
  @oid_ext_key_usage {2, 5, 29, 37}
  @oid_server_auth {1, 3, 6, 1, 5, 5, 7, 3, 1}
  @oid_client_auth {1, 3, 6, 1, 5, 5, 7, 3, 2}

  # DN OIDs
  @oid_common_name {2, 5, 4, 3}
  @oid_country {2, 5, 4, 6}
  @oid_locality {2, 5, 4, 7}
  @oid_province {2, 5, 4, 8}
  @oid_org {2, 5, 4, 10}
  @oid_org_unit {2, 5, 4, 11}
  @oid_postal_code {2, 5, 4, 17}
  @oid_street {2, 5, 4, 9}

  @root_ca_validity_years 10

  defmodule CertificateAuthority do
    @moduledoc """
    Represents a Certificate Authority (CA) with its certificate and private key.
     - `certificate`: PEM-encoded CA certificate
     - `private_key`: PEM-encoded private key corresponding to the CA certificate
    """
    @type t :: %__MODULE__{
            # PEM encoded
            private_key: binary(),
            # PEM encoded
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
     This struct can be used for both Root CA creation and CSR generation.
     - `organization`: The organization name (O)
     - `organizational_unit`: The organizational unit (OU)
     - `country`: The country code (C)
     - `province`: The state or province name (ST)
     - `locality`: The locality or city name (L)
     - `street_address`: The street address
     - `postal_code`: The postal code
     - `common_name`: The common name (CN), often used for the server's hostname in TLS certs
     Note: For a Root CA, only Organization and Country are strictly required. Other fields can be optional.
     For CSRs, the fields can be used to populate the Subject DN as needed.
     Validation will ensure that at least Organization and Country are provided for Root CA creation.
     For CSRs, the presence of fields is flexible, but typically Common Name or Organization is included.
     This struct serves as a convenient way to pass around certificate subject information and can be extended with additional fields if necessary.
     When creating a Root CA, the same Config can be used for both the issuer and subject since it's self-signed. For CSRs, the Config populates the subject of the CSR.
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
      end

      :ok
    end
  end

  defmodule CSRCertificate do
    @moduledoc """
    Represents a Certificate Signing Request (CSR) along with its associated key pair.
     - `csr`: PEM-encoded CSR
     - `private_key`: PEM-encoded private key corresponding to the CSR's public key
     - `public_key`: PEM-encoded public key included in the CSR
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
  @doc """
  Creates a root certificate authority (CA) using Ed25519.
  """
  def create_root_ca(%Config{} = config) do
    op = :create_root_ca

    with :ok <- Config.validate(config, :root_ca),
         {:ok, serial} <- generate_serial(),
         {pub_key, priv_key} <- generate_ed25519_keypair(),
         # Build TBS (To Be Signed) Certificate
         tbs_cert = build_ca_tbs(config, serial, pub_key),
         # Sign the certificate (Self-signed)
         {:ok, der_cert} <- sign_tbs(tbs_cert, priv_key),
         {:ok, pem_cert} <- encode_pem(:certificate, der_cert),
         {:ok, pem_key} <- encode_private_key(priv_key) do
      {:ok,
       %CertificateAuthority{
         certificate: pem_cert,
         private_key: pem_key
       }}
    else
      {:error, reason} ->
        {:error, %Error{message: reason, op: op}}

      {:error, reason, internal} ->
        {:error, %Error{message: reason, err: internal, op: op}}
    end
  end

  @spec load_root_ca(binary(), binary()) :: {:ok, CertificateAuthority.t()} | {:error, Error.t()}
  @doc """
  Loads an existing root CA certificate and private key from PEM-encoded data.
  """
  def load_root_ca(ca_pem, key_pem) do
    op = :load_root_ca

    with {:ok, ca_cert_rec} <- decode_pem_cert(ca_pem),
         {:ok, priv_key} <- decode_pem_private_key(key_pem),
         :ok <- validate_ca_constraints(ca_cert_rec),
         :ok <- verify_key_matches_cert(priv_key, ca_cert_rec),
         :ok <- check_validity_period(ca_cert_rec) do
      {:ok,
       %CertificateAuthority{
         certificate: ca_pem,
         private_key: key_pem
       }}
    else
      {:error, reason} -> {:error, %Error{message: reason, op: op}}
      {:error, reason, internal} -> {:error, %Error{message: reason, err: internal, op: op}}
    end
  end

  @spec create_csr_certificate(Config.t()) :: {:ok, CSRCertificate.t()} | {:error, Error.t()}
  @doc """
  Creates a Certificate Signing Request (CSR) with Ed25519 keys.
  """
  def create_csr_certificate(%Config{} = config) do
    op = :create_csr

    with :ok <- Config.validate(config, :csr),
         {pub_key, priv_key} <- generate_ed25519_keypair(),
         subject = config_to_rdn(config),
         csr_info =
           cert_req_info(
             version: :v1,
             subject: subject,
             subjectPKInfo:
               spki(
                 algorithm: algo_id(algorithm: @oid_ed25519, parameters: :asn1_NOVALUE),
                 subjectPublicKey: pub_key
               ),
             attributes: []
           ),
         # Sign CSR
         {:ok, der_csr} <- sign_csr_info(csr_info, priv_key),
         {:ok, pem_csr} <- encode_pem(:certification_request, der_csr),
         {:ok, pem_priv} <- encode_private_key(priv_key),
         {:ok, pem_pub} <- encode_public_key(pub_key) do
      {:ok,
       %CSRCertificate{
         csr: pem_csr,
         private_key: pem_priv,
         public_key: pem_pub
       }}
    else
      {:error, reason} -> {:error, %Error{message: reason, op: op}}
      {:error, reason, internal} -> {:error, %Error{message: reason, err: internal, op: op}}
    end
  end

  @spec sign_csr(CertificateAuthority.t(), binary(), integer()) ::
          {:ok, binary()} | {:error, Error.t()}
  @doc """
  Signs a PEM-encoded CSR using the provided CA and returns a PEM-encoded certificate.
  """
  def sign_csr(%CertificateAuthority{} = ca, csr_pem, validity_days) do
    op = :sign_csr

    with {:ok, ca_cert_rec} <- decode_pem_cert(ca.certificate),
         {:ok, ca_priv_key} <- decode_pem_private_key(ca.private_key),
         {:ok, csr_rec} <- decode_pem_csr(csr_pem),
         :ok <- verify_csr_signature(csr_rec),
         {:ok, serial} <- generate_serial(),
         tbs_cert = build_client_tbs(csr_rec, ca_cert_rec, serial, validity_days),
         {:ok, der_cert} <- sign_tbs(tbs_cert, ca_priv_key),
         {:ok, pem_cert} <- encode_pem(:certificate, der_cert) do
      {:ok, pem_cert}
    else
      {:error, reason} -> {:error, %Error{message: reason, op: op}}
      {:error, reason, internal} -> {:error, %Error{message: reason, err: internal, op: op}}
    end
  end

  # ============================================================================
  # Internal Builders & Helpers
  # ============================================================================

  defp build_ca_tbs(config, serial, pub_key) do
    subject = config_to_rdn(config)
    {not_before, not_after} = validity_period(@root_ca_validity_years * 365)

    # Extensions
    basic_constraints =
      extension(
        extnID: @oid_basic_constraints,
        critical: true,
        extnValue:
          :public_key.der_encode(:BasicConstraints, {:BasicConstraints, true, :asn1_NOVALUE})
      )

    # KeyUsage: digitalSignature (0), keyCertSign (5) -> bits 0 and 5 set.
    # In ASN.1 BIT STRING, this maps to [digitalSignature, keyCertSign]
    key_usage =
      extension(
        extnID: @oid_key_usage,
        critical: true,
        extnValue: :public_key.der_encode(:KeyUsage, [:digitalSignature, :keyCertSign])
      )

    ext_key_usage =
      extension(
        extnID: @oid_ext_key_usage,
        critical: false,
        extnValue:
          :public_key.der_encode(:ExtKeyUsageSyntax, [@oid_server_auth, @oid_client_auth])
      )

    tbs_cert(
      version: :v3,
      serialNumber: serial,
      signature: algo_id(algorithm: @oid_ed25519, parameters: :asn1_NOVALUE),
      # Self-signed: Issuer == Subject
      issuer: subject,
      validity: validity(notBefore: not_before, notAfter: not_after),
      subject: subject,
      subjectPublicKeyInfo:
        spki(
          algorithm: algo_id(algorithm: @oid_ed25519, parameters: :asn1_NOVALUE),
          subjectPublicKey: pub_key
        ),
      extensions: [basic_constraints, key_usage, ext_key_usage]
    )
  end

  defp build_client_tbs(csr_rec, ca_cert_rec, serial, validity_days) do
    csr_info = cert_req(csr_rec, :certificationRequestInfo)
    subject = cert_req_info(csr_info, :subject)
    public_key_info = cert_req_info(csr_info, :subjectPKInfo)
    {not_before, not_after} = validity_period(validity_days)

    # Extract Issuer from CA Certificate (The CA is the issuer of this new cert)
    ca_tbs = otp_cert(ca_cert_rec, :tbsCertificate)
    issuer = tbs_cert(ca_tbs, :subject)

    # Extensions for client auth
    key_usage =
      extension(
        extnID: @oid_key_usage,
        critical: true,
        extnValue: :public_key.der_encode(:KeyUsage, [:digitalSignature])
      )

    ext_key_usage =
      extension(
        extnID: @oid_ext_key_usage,
        critical: false,
        extnValue: :public_key.der_encode(:ExtKeyUsageSyntax, [@oid_client_auth])
      )

    tbs_cert(
      version: :v3,
      serialNumber: serial,
      signature: algo_id(algorithm: @oid_ed25519, parameters: :asn1_NOVALUE),
      issuer: issuer,
      validity: validity(notBefore: not_before, notAfter: not_after),
      subject: subject,
      subjectPublicKeyInfo: public_key_info,
      extensions: [key_usage, ext_key_usage]
    )
  end

  defp sign_tbs(tbs_record, priv_key) do
    try do
      der = :public_key.pkix_encode(:OTPTBSCertificate, tbs_record, :otp)
      signature = :public_key.sign(der, :none, priv_key)

      cert =
        otp_cert(
          tbsCertificate: tbs_record,
          signatureAlgorithm: algo_id(algorithm: @oid_ed25519, parameters: :asn1_NOVALUE),
          signature: signature
        )

      {:ok, :public_key.pkix_encode(:OTPCertificate, cert, :otp)}
    rescue
      e -> {:error, "failed to sign certificate: #{inspect(e)}"}
    end
  end

  defp sign_csr_info(info_record, priv_key) do
    try do
      der = :public_key.pkix_encode(:CertificationRequestInfo, info_record, :otp)
      signature = :public_key.sign(der, :none, priv_key)

      csr =
        cert_req(
          certificationRequestInfo: info_record,
          signatureAlgorithm: algo_id(algorithm: @oid_ed25519, parameters: :asn1_NOVALUE),
          signature: signature
        )

      {:ok, :public_key.pkix_encode(:CertificationRequest, csr, :otp)}
    rescue
      e -> {:error, "failed to sign CSR: #{inspect(e)}"}
    end
  end

  defp verify_csr_signature(csr_rec) do
    # public_key:pkix_verify_hostname/2 is not what we want. We want verify signature.
    # We must extract the blob, signature, and public key manually because :public_key
    # often works on Certificates, not CSRs, for high-level verification.
    info = cert_req(csr_rec, :certificationRequestInfo)
    sig = cert_req(csr_rec, :signature)

    # Re-encode info to get the signed bytes
    signed_data = :public_key.pkix_encode(:CertificationRequestInfo, info, :otp)

    # Extract Public Key from CSR
    spki_rec = cert_req_info(info, :subjectPKInfo)
    der_key = spki(spki_rec, :subjectPublicKey)

    # Ed25519 keys in SPKI are wrapped; for verification we need the raw key.
    # However, :public_key.verify can handle the SPKI record format if we pass the whole record or correct type.
    # For Ed25519, the key is the raw 32 bytes.
    case :public_key.verify(signed_data, :none, sig, {spki_rec, :asn1_NOVALUE}) do
      true -> :ok
      false -> {:error, "CSR signature check failed"}
    end
  end

  defp verify_key_matches_cert(priv_key, cert_rec) do
    # priv_key is raw 32 bytes (Ed25519 private seed) or key map?
    # :crypto.generate_key returns {Pub, Priv}. Priv is the seed.
    # We can derive the public key from the private key and compare it to the cert's public key.

    # Note: In pure Erlang :crypto with Ed25519, we cannot easily re-derive public from private
    # without running generate again or using a library, BUT if we assume the priv_key passed here
    # is the raw seed, we can check.

    # Actually, :crypto.generate_key(:eddsa, :ed25519, priv_key) regenerates the pair.
    {derived_pub, _} = :crypto.generate_key(:eddsa, :ed25519, priv_key)

    tbs = otp_cert(cert_rec, :tbsCertificate)
    spki_rec = tbs_cert(tbs, :subjectPublicKeyInfo)
    cert_pub = spki(spki_rec, :subjectPublicKey)

    if derived_pub == cert_pub do
      :ok
    else
      {:error, "private key does not match certificate public key"}
    end
  end

  defp validate_ca_constraints(cert_rec) do
    tbs = otp_cert(cert_rec, :tbsCertificate)
    extensions = tbs_cert(tbs, :extensions)

    # Find BasicConstraints
    case find_extension(extensions, @oid_basic_constraints) do
      nil ->
        {:error, "provided certificate is not a CA (no BasicConstraints)"}

      val ->
        case :public_key.der_decode(:BasicConstraints, val) do
          {:BasicConstraints, true, _} -> :ok
          _ -> {:error, "provided certificate is not a CA"}
        end
    end
  end

  defp check_validity_period(cert_rec) do
    tbs = otp_cert(cert_rec, :tbsCertificate)
    val = tbs_cert(tbs, :validity)
    not_before = validity(val, :notBefore)
    not_after = validity(val, :notAfter)

    now = :os.system_time(:second)

    if now >= parse_asn1_time(not_before) and now <= parse_asn1_time(not_after) do
      :ok
    else
      {:error, "CA certificate is not currently valid"}
    end
  end

  defp find_extension(extensions, oid) do
    case Enum.find(extensions, fn ext -> extension(ext, :extnID) == oid end) do
      nil -> nil
      rec -> extension(rec, :extnValue)
    end
  end

  # ============================================================================
  # Crypto & Encoding Helpers
  # ============================================================================

  defp generate_ed25519_keypair do
    :crypto.generate_key(:eddsa, :ed25519)
  end

  defp generate_serial do
    serial = :crypto.strong_rand_bytes(16) |> :binary.decode_unsigned()
    {:ok, serial}
  end

  defp encode_pem(type, der) do
    entry = :public_key.pem_entry_encode(type, der)
    {:ok, :public_key.pem_encode([entry])}
  end

  defp decode_pem_cert(pem_data) do
    case :public_key.pem_decode(pem_data) do
      [{:Certificate, der, _} | _] ->
        {:ok, :public_key.pkix_decode_cert(der, :otp)}

      _ ->
        {:error, "failed to decode CA certificate"}
    end
  end

  defp decode_pem_csr(pem_data) do
    case :public_key.pem_decode(pem_data) do
      [{:CertificationRequest, der, _} | _] ->
        {:ok, :public_key.der_decode(:CertificationRequest, der)}

      _ ->
        {:error, "failed to decode CSR"}
    end
  end

  defp decode_pem_private_key(pem_data) do
    case :public_key.pem_decode(pem_data) do
      [entry | _] ->
        try do
          info = :public_key.pem_entry_decode(entry)

          case info do
            {_algo, priv_key} when is_binary(priv_key) -> {:ok, priv_key}
            key when is_binary(key) -> {:ok, key}
            other -> {:error, "unsupported private key structure: #{inspect(other)}"}
          end
        rescue
          _ -> {:error, "failed to parse private key"}
        end

      [] ->
        {:error, "no PEM block found"}
    end
  end

  defp encode_private_key(priv_key) do
    # Wrap Ed25519 private key in PKCS8
    # 1.3.101.112 is Ed25519
    # Wrapper: OneAsymmetricKey (RFC 8410)
    # But :public_key.pem_encode needs a specific entry format.
    # The simplest way for Ed25519 is using the type :private_key with the correct DER structure.
    # We construct the PKCS8 structure manually or use :public_key logic.

    # Standard ASN.1 for Ed25519 private key is an OctetString inside the PrivateKeyInfo
    # CurvePrivateKey ::= OCTET STRING

    # We use a helper to wrap it into PKCS8 which is standard for storage
    wrapper =
      {
        :PrivateKeyInfo,
        :v1,
        {:AlgorithmIdentifier, @oid_ed25519, :asn1_NOVALUE},
        # The private key for Ed25519 is an OCTET STRING encoded in the privateKey field
        :public_key.der_encode(:CurvePrivateKey, priv_key),
        :asn1_NOVALUE
      }

    der = :public_key.der_encode(:PrivateKeyInfo, wrapper)
    # PEM type "PRIVATE KEY" matches PKCS8
    encode_pem(:PrivateKeyInfo, der)
  end

  defp encode_public_key(pub_key) do
    # SubjectPublicKeyInfo for Ed25519
    spki =
      spki(
        algorithm: algo_id(algorithm: @oid_ed25519, parameters: :asn1_NOVALUE),
        subjectPublicKey: pub_key
      )

    der = :public_key.der_encode(:SubjectPublicKeyInfo, spki)
    encode_pem(:SubjectPublicKeyInfo, der)
  end

  # ============================================================================
  # Time & Formatting
  # ============================================================================

  defp validity_period(days) do
    now = DateTime.utc_now()
    future = DateTime.add(now, days, :day)
    {format_asn1_time(now), format_asn1_time(future)}
  end

  # ASN.1 GeneralizedTime/UTCTime formatting
  defp format_asn1_time(dt) do
    # public_key usually expects charlist format 'YYYYMMDDHHMMSSZ' (GeneralizedTime)
    # or 'YYMMDDHHMMSSZ' (UTCTime) depending on year.
    # For simplicity and correctness > 2050, we usually use GeneralizedTime.
    str = Calendar.strftime(dt, "%Y%m%d%H%M%SZ")
    {:generalTime, String.to_charlist(str)}
  end

  defp parse_asn1_time({:utcTime, chars}), do: parse_time_str(chars, :utc)
  defp parse_asn1_time({:generalTime, chars}), do: parse_time_str(chars, :gen)

  defp parse_time_str(chars, type) do
    str = List.to_string(chars)

    case type do
      :utc ->
        # simplistic parsing for YYMMDD...
        # In a real app, robustly parse 2-digit year.
        {:ok, dt, 0} =
          DateTime.from_iso8601(
            "20#{String.slice(str, 0, 2)}-#{String.slice(str, 2, 2)}-#{String.slice(str, 4, 2)}T#{String.slice(str, 6, 2)}:#{String.slice(str, 8, 2)}:#{String.slice(str, 10, 2)}Z"
          )

        DateTime.to_unix(dt)

      :gen ->
        {:ok, dt, 0} =
          DateTime.from_iso8601(
            "#{String.slice(str, 0, 4)}-#{String.slice(str, 4, 2)}-#{String.slice(str, 6, 2)}T#{String.slice(str, 8, 2)}:#{String.slice(str, 10, 2)}:#{String.slice(str, 12, 2)}Z"
          )

        DateTime.to_unix(dt)
    end
  end

  defp config_to_rdn(config) do
    # Use :rdnSequence format: [[AttributeTypeAndValue]]
    # AttributeTypeAndValue :: {type, value}
    # Note: Value needs to be encoded as DirectoryString or PrintableString usually.
    # The :public_key.pkix_encode handles the string wrapping if we pass standard types?
    # No, usually better to explicitly wrap string types: {:utf8String, "binary"}

    attrs = [
      {@oid_org, config.organization},
      {@oid_org_unit, config.organizational_unit},
      {@oid_country, config.country},
      {@oid_province, config.province},
      {@oid_locality, config.locality},
      {@oid_street, config.street_address},
      {@oid_postal_code, config.postal_code},
      {@oid_common_name, config.common_name}
    ]

    # Filter nil/empty and map to RDN structure
    rdn_list =
      attrs
      |> Enum.reject(fn {_oid, v} -> v in [nil, ""] end)
      |> Enum.map(fn {oid, val} ->
        [attribute(type: oid, value: {:utf8String, val})]
      end)

    {:rdnSequence, rdn_list}
  end
end
