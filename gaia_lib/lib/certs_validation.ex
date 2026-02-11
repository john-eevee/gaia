defmodule GaiaLib.CertsValidation do
  @moduledoc """
  Helpers for inspecting X.509 certificates using the `x509` library.

  Provides a small helper to determine whether a certificate should be
  considered a Root CA. The check uses these heuristics:

  1. `basicConstraints` extension present and `cA = TRUE`
  2. Certificate is self-signed (verified with its own public key)
  3. (optional) If `keyUsage` is present, it contains `:keyCertSign` or
     `:cRLSign`.

  The main function `root_ca?/1` accepts a PEM string, DER binary, or an
  already-decoded OTP certificate and returns `true` when the certificate
  looks like a root CA, `false` otherwise.
  """

  alias GaiaLib.CertsValidation.PEMError

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

  @spec root_ca?(binary() | tuple()) :: boolean()
  def root_ca?(pem_or_der_or_cert) do
    with {:ok, cert} <- ensure_cert(pem_or_der_or_cert),
         true <- basic_constraints_ca?(cert),
         true <- :public_key.pkix_is_self_signed(cert) do
      key_usage_allows_ca?(cert)
    else
      _ -> false
    end
  end

  # Try to normalize input into an OTP certificate record using X509 helpers
  defp ensure_cert(cert) when is_binary(cert) do
    cond do
      String.contains?(cert, "-----BEGIN") ->
        case X509.Certificate.from_pem(cert) do
          {:ok, c} -> {:ok, c}
          {:error, _} -> {:error, :invalid_pem}
        end

      true ->
        case X509.Certificate.from_der(cert) do
          {:ok, c} -> {:ok, c}
          {:error, _} -> {:error, :invalid_der}
        end
    end
  end

  defp ensure_cert(cert), do: {:ok, cert}

  # Check Basic Constraints extension indicates CA:TRUE
  defp basic_constraints_ca?(cert) do
    case X509.Certificate.extension(cert, :basic_constraints) do
      nil ->
        false

      {:Extension, _oid, _critical, value} ->
        # value may already be decoded or still be DER-encoded depending on
        # OTP/X509 versions; try to decode when it's a binary.
        decoded =
          cond do
            is_binary(value) ->
              try do
                :public_key.der_decode(:BasicConstraints, value)
              rescue
                _ -> value
              end

            true ->
              value
          end

        case decoded do
          {:BasicConstraints, true, _path} -> true
          {:BasicConstraints, true} -> true
          {true, _path} -> true
          true -> true
          _ -> false
        end

      _ ->
        false
    end
  end

  # If keyUsage is present, require keyCertSign or cRLSign; otherwise allow.
  defp key_usage_allows_ca?(cert) do
    case X509.Certificate.extension(cert, :key_usage) do
      {:Extension, _oid, _critical, usages} when is_list(usages) ->
        :keyCertSign in usages or :cRLSign in usages

      _ ->
        true
    end
  end

  @doc """
  Validate that the given string is PEM armored.

  Accepts one or more PEM blocks (for example a cert chain or key + cert).
  Returns `:ok` when every PEM block decodes as base64, otherwise returns
  `{:error, reason}` describing the failure.
  """
  @spec validate_pem_armor(binary()) :: :ok | {:error, PEMError.t()}
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

  @doc """
  Check whether the given certificate corresponds to the given private key.

  Accepts the same input formats as `root_ca?/1` and `validate_pem_armor/1`:
  PEM string, DER binary, or an already-decoded OTP certificate / private key
  structure. Returns `true` when the private key matches the certificate's
  public key, `false` otherwise.
  """
  @spec certificate_matches_private_key?(binary() | tuple(), binary() | tuple()) :: boolean()
  def certificate_matches_private_key?(pem_or_der_or_cert, pem_or_der_or_key) do
    with {:ok, cert} <- ensure_cert(pem_or_der_or_cert),
         {:ok, priv} <- ensure_private_key(pem_or_der_or_key) do
      pub = X509.Certificate.public_key(cert)
      private_key_matches_public?(priv, pub)
    else
      _ -> false
    end
  end

  # Normalize various private key inputs into an OTP private key structure
  defp ensure_private_key(key) when is_binary(key) do
    cond do
      String.contains?(key, "-----BEGIN") ->
        case X509.PrivateKey.from_pem(key) do
          {:ok, k} -> {:ok, k}
          {:error, _} -> {:error, :invalid_pem}
        end

      true ->
        case X509.PrivateKey.from_der(key) do
          {:ok, k} -> {:ok, k}
          {:error, _} -> {:error, :invalid_der}
        end
    end
  end

  defp ensure_private_key(key), do: {:ok, key}

  # Try to determine whether a private key corresponds to the given public
  # key by attempting to sign+verify a short random message. Different
  # key types require different signing algorithms, so we try a small list
  # of likely candidates and accept the first that verifies.
  defp private_key_matches_public?(priv, pub) do
    algos = candidate_algorithms_for_pub(pub)
    message = :crypto.strong_rand_bytes(32)

    Enum.any?(algos, fn algo ->
      try do
        sig = :public_key.sign(message, algo, priv)

        case :public_key.verify(message, algo, sig, pub) do
          true -> true
          _ -> false
        end
      rescue
        _ -> false
      end
    end)
  end

  defp candidate_algorithms_for_pub({:RSAPublicKey, _, _}),
    do: [:rsa_pkcs1_sha256, :rsa_pkcs1_sha512, :sha256, :sha512]

  # Ed25519 uses the EDDSA algorithm (OID 1.3.101.112)
  defp candidate_algorithms_for_pub({{:ECPoint, _}, {:namedCurve, {1, 3, 101, 112}}}),
    do: [:eddsa]

  # Generic EC keys - prefer SHA-2 family for ECDSA
  defp candidate_algorithms_for_pub({{:ECPoint, _}, {:namedCurve, _}}),
    do: [:sha256, :sha384, :sha512]

  # Fallback: try common signing algos
  defp candidate_algorithms_for_pub(_), do: [:sha256, :sha512, :eddsa]
end
