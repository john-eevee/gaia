defmodule GaiaLib.Certs do
  @moduledoc """
  Mtls provides functionality to generate Root CA certificates, create CSRs,
  and sign certificates using Ed25519 keys via the x509 library.
  """

  alias GaiaLib.Certs.{
    CertificatePair,
    CSRCertificate,
    CertConfig,
    ConfigValidationError
  }

  alias GaiaLib.CertsValidation

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

  defmodule Error do
    @moduledoc """
    Generic error used by certs APIs in tests.
    Fields:
      - `message`: human readable description
      - `op`: the operation that failed
      - `err`: optional internal error
    """
    defexception [:message, :op, :err]

    @type t :: %__MODULE__{message: String.t(), op: atom() | nil, err: any() | nil}

    def message(%__MODULE__{message: msg, err: nil}), do: msg
    def message(%__MODULE__{message: msg, err: err}), do: "#{msg} - #{inspect(err)}"
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
          {:error, "Config validation failed: Organization is required for Root CA"}

        is_nil(config.country) or config.country == "" ->
          {:error, "Config validation failed: Country is required for Root CA"}

        true ->
          :ok
      end
    end

    def validate(config, type = :csr) do
      no_common_name = is_nil(config.common_name) or config.common_name == ""
      no_organization = is_nil(config.organization) or config.organization == ""

      if no_common_name and no_organization do
        {:error, "Config validation failed: CSR requires either Common Name or Organization"}
      else
        :ok
      end
    end

    def to_rdn(config) do
      # Only include attribute keys supported by X509.RDNSequence.new_attr/1
      allowed = ["O", "OU", "C", "ST", "L", "CN"]

      rnd_items =
        [
          {"O", config.organization},
          {"OU", config.organizational_unit},
          {"C", config.country},
          {"ST", config.province},
          {"L", config.locality},
          {"CN", config.common_name}
        ]
        |> Enum.filter(fn {_k, v} -> not is_nil(v) and v != "" end)
        |> Enum.filter(fn {k, _v} -> k in allowed end)

      case rnd_items do
        [] -> "/"
        _ -> "/" <> Enum.map_join(rnd_items, "/", fn {k, v} -> "#{k}=#{v}" end)
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
          validity: validity,
          extensions: [
            basic_constraints: X509.Certificate.Extension.basic_constraints(true),
            key_usage:
              X509.Certificate.Extension.key_usage([:digitalSignature, :keyCertSign, :cRLSign]),
            subject_key_identifier: true,
            authority_key_identifier: true
          ]
        )

      certificate_pem = X509.Certificate.to_pem(certificate)
      private_key_pem = X509.PrivateKey.to_pem(private_key)

      %CertificatePair{
        certificate: certificate_pem,
        private_key: private_key_pem
      }
    end

    case CertConfig.validate(config, :root_ca) do
      :ok ->
        {:ok, certificate.()}

      {:error, msg} ->
        {:error, %Error{message: msg, op: :create_root_ca}}
    end
  end

  def create_csr(config) do
    csr_fun = fn ->
      private_key = X509.PrivateKey.new_ec(@key_curve)
      rdn = CertConfig.to_rdn(config)
      csr = X509.CSR.new(private_key, rdn)
      csr_pem = X509.CSR.to_pem(csr)
      private_key_pem = X509.PrivateKey.to_pem(private_key)

      # Extract public key and encode to PEM using X509 helpers
      pub = X509.CSR.public_key(csr)
      pub_pem = X509.PublicKey.to_pem(pub)

      %CSRCertificate{csr: csr_pem, private_key: private_key_pem, public_key: pub_pem}
    end

    case CertConfig.validate(config, :csr) do
      :ok -> {:ok, csr_fun.()}
      {:error, msg} -> {:error, %Error{message: msg, op: :create_csr}}
    end
  end

  @doc """
  Sign a CSR using the given root CA pair.

  `root_ca` must be a map/struct with `:certificate` and `:private_key` fields
  (the same shape returned by `create_root_ca/1`). `csr_pem` is a CSR PEM
  string. Returns `{:ok, cert_pem}` on success or `{:error, %Error{}}` on
  failure.
  """
  # Accept both call orders for convenience: (csr_pem, root_ca, days) or (root_ca, csr_pem, days)
  def sign_csr(%{certificate: _cert, private_key: _priv} = root_ca, csr_pem, validity_days)
      when is_binary(csr_pem) do
    sign_csr(csr_pem, root_ca, validity_days)
  end

  def sign_csr(csr_pem, root_ca, validity_days) when is_binary(csr_pem) do
    # Parse CSR
    with {:ok, csr} <- X509.CSR.from_pem(csr_pem),
         %{certificate: certificate_pem, private_key: private_key_pem} <- root_ca,
         {:ok, ca_cert} <- X509.Certificate.from_pem(certificate_pem),
         {:ok, ca_priv} <- X509.PrivateKey.from_pem(private_key_pem),
         true <- CertsValidation.root_ca?(ca_cert),
         true <- CertsValidation.certificate_matches_private_key?(ca_cert, ca_priv) do
      pub = X509.CSR.public_key(csr)
      subject = X509.CSR.subject(csr)
      serial = :crypto.strong_rand_bytes(16) |> :crypto.bytes_to_integer()
      validity = X509.Certificate.Validity.days_from_now(validity_days)

      cert =
        X509.Certificate.new(pub, subject, ca_cert, ca_priv,
          template: :server,
          serial: serial,
          validity: validity
        )

      {:ok, X509.Certificate.to_pem(cert)}
    else
      {:error, {:malformed, _}} = err ->
        {:error, %Error{message: "Invalid CSR PEM", op: :sign_csr, err: err}}

      {:error, reason} ->
        {:error, %Error{message: "Sign CSR failed", op: :sign_csr, err: reason}}

      false ->
        {:error, %Error{message: "private key does not match", op: :sign_csr}}

      _ ->
        {:error, %Error{message: "invalid ca", op: :sign_csr}}
    end
  end

  def sign_csr(_, _, _), do: {:error, %Error{message: "invalid csr", op: :sign_csr}}

  @doc """
  Load and validate a root CA from PEMs or der/binary inputs.

  Returns `{:ok, %CertificatePair{}}` when validation succeeds or
  `{:error, %Error{}}` when it fails.
  """
  def load_root_ca(cert_pem_or_der, priv_pem_or_der) do
    cert_result =
      case X509.Certificate.from_pem(cert_pem_or_der) do
        {:ok, cert} -> {:ok, cert}
        {:error, _} -> X509.Certificate.from_der(cert_pem_or_der)
      end

    priv_result =
      case X509.PrivateKey.from_pem(priv_pem_or_der) do
        {:ok, priv} -> {:ok, priv}
        {:error, _} -> X509.PrivateKey.from_der(priv_pem_or_der)
      end

    with {:ok, cert} <- cert_result,
         {:ok, priv} <- priv_result,
         true <- CertsValidation.root_ca?(cert),
         true <- CertsValidation.certificate_matches_private_key?(cert, priv) do
      {:ok,
       %CertificatePair{
         certificate: X509.Certificate.to_pem(cert),
         private_key: X509.PrivateKey.to_pem(priv)
       }}
    else
      {:error, _} = err ->
        {:error, %Error{message: "Invalid certificate or key", op: :load_root_ca, err: err}}

      false ->
        {:error, %Error{message: "private key does not match", op: :load_root_ca}}

      _ ->
        {:error, %Error{message: "certificate is not a root CA", op: :load_root_ca}}
    end
  end

  @doc """
  Like `load_root_ca/2` but accepts an optional password for encrypted
  private key PEMs. The password should be a binary (UTF-8) or nil.
  Returns `{:ok, %CertificatePair{}}` or `{:error, %Error{}}`.
  """
  def load_root_ca(cert_pem_or_der, priv_pem_or_der, password) do
    cert_result =
      case X509.Certificate.from_pem(cert_pem_or_der) do
        {:ok, cert} -> {:ok, cert}
        {:error, _} -> X509.Certificate.from_der(cert_pem_or_der)
      end

    priv_result =
      case X509.PrivateKey.from_pem(priv_pem_or_der, password: password) do
        {:ok, priv} -> {:ok, priv}
        {:error, _} -> X509.PrivateKey.from_der(priv_pem_or_der)
      end

    with {:ok, cert} <- cert_result,
         {:ok, priv} <- priv_result,
         true <- CertsValidation.root_ca?(cert),
         true <- CertsValidation.certificate_matches_private_key?(cert, priv) do
      {:ok,
       %CertificatePair{
         certificate: X509.Certificate.to_pem(cert),
         private_key: X509.PrivateKey.to_pem(priv)
       }}
    else
      {:error, _} = err ->
        {:error, %Error{message: "Invalid certificate or key", op: :load_root_ca, err: err}}

      false ->
        {:error, %Error{message: "private key does not match", op: :load_root_ca}}

      _ ->
        {:error, %Error{message: "certificate is not a root CA", op: :load_root_ca}}
    end
  end

  @doc """
  Write a CertificatePair to disk. `path` should be a directory; the function
  will write two files inside it: `root.crt` and `root.key`.

  Options:
    * `:password` - optional PEM password to encrypt the private key (binary)

  Returns `:ok` or `{:error, reason}`.
  """
  def write_root_ca(
        %CertificatePair{certificate: cert_pem, private_key: priv_pem},
        path,
        opts \\ []
      )
      when is_binary(path) do
    password = Keyword.get(opts, :password)

    try do
      File.mkdir_p!(path)

      cert_path = Path.join(path, "root.crt")
      key_path = Path.join(path, "root.key")

      :ok = File.write!(cert_path, cert_pem)

      # If password provided, attempt to re-encode the private key with the
      # password using X509.PrivateKey.to_pem/2. Otherwise write as-is.
      pem_to_write =
        if password && is_binary(password) do
          # Try to parse and re-encode using the provided password
          case X509.PrivateKey.from_pem(priv_pem) do
            {:ok, priv} ->
              X509.PrivateKey.to_pem(priv, password: password)

            {:error, _} ->
              # If we can't parse, fall back to writing original
              priv_pem
          end
        else
          priv_pem
        end

      :ok = File.write!(key_path, pem_to_write)

      :ok
    rescue
      e -> {:error, e}
    end
  end
end
