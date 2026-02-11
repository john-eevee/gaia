defmodule GaiaLib.CertsIntegrationTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  alias GaiaLib.Certs
  alias GaiaLib.Certs.CertConfig

  test "generate CA -> save -> load -> create CSR -> sign -> verify" do
    tmp_dir =
      Path.join(System.tmp_dir!(), "gaia_certs_integration_#{:erlang.system_time(:millisecond)}")

    ca_config = %CertConfig{organization: "Integration CA", country: "US"}
    {:ok, ca} = Certs.create_root_ca(ca_config)

    # Save to disk
    assert :ok = Certs.write_root_ca(ca, tmp_dir)

    cert_path = Path.join(tmp_dir, "root.crt")
    key_path = Path.join(tmp_dir, "root.key")

    assert File.exists?(cert_path)
    assert File.exists?(key_path)

    # Load back from disk
    cert_pem = File.read!(cert_path)
    key_pem = File.read!(key_path)

    assert {:ok, loaded_ca} = Certs.load_root_ca(cert_pem, key_pem)

    # Create CSR and sign using reloaded CA
    csr_config = %CertConfig{common_name: "svc.local", organization: "svc"}
    {:ok, csr} = Certs.create_csr(csr_config)

    assert {:ok, signed_pem} = Certs.sign_csr(loaded_ca, csr.csr, 365)

    # Basic checks
    assert String.starts_with?(signed_pem, "-----BEGIN CERTIFICATE-----")

    # Verify signature manually using :public_key APIs
    {:ok, ca_struct} = X509.Certificate.from_pem(loaded_ca.certificate)
    {:ok, signed_struct} = X509.Certificate.from_pem(signed_pem)

    signed_der = X509.Certificate.to_der(signed_struct)
    {:OTPCertificate, tbs, _sig_alg, signature} = :public_key.pkix_decode_cert(signed_der, :otp)
    tbs_der = :public_key.pkix_encode(:OTPTBSCertificate, tbs, :otp)

    ca_pub = X509.Certificate.public_key(ca_struct)
    assert :public_key.verify(tbs_der, :eddsa, signature, ca_pub)

    # Clean up
    File.rm_rf!(tmp_dir)
  end
end
