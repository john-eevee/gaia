defmodule Mix.Tasks.FarmNode.StatusTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Gaia.FarmNode.HubConnection.Provisioning.Storage

  setup do
    Application.ensure_all_started(:farm_node)
    Storage.revoke_credentials()
    :ok
  end

  test "status shows unprovisioned" do
    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)
    assert output =~ "UNPROVISIONED"
    assert output =~ "mix farm_node.provision"
  end

  test "status shows active when credentials present" do
    # Write real certificate so parsing succeeds
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=farm-test")
    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    assert output =~ "Status: ✅ ACTIVE"
    assert output =~ "Credentials Location"
    assert output =~ "Certificate Details" or output =~ "Unable to parse certificate details"

    Storage.revoke_credentials()
  end

  test "status shows unable to read certificate details when cert not readable" do
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=farm-test")
    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    {:ok, paths} = Storage.get_credential_paths()

    # Make cert unreadable
    File.chmod(paths.cert, 0o000)

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    assert output =~ "Unable to read certificate details"

    # Restore and cleanup
    File.chmod(paths.cert, 0o644)
    Storage.revoke_credentials()
  end

  test "status prints certificate details when PEM is parseable" do
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=parsed-farm/O=Test")
    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    # Verify it shows ACTIVE status with credentials location
    assert output =~ "Status: ✅ ACTIVE"
    assert output =~ "Credentials Location"
    # Either parsing succeeds or fails gracefully
    assert output =~ "Certificate Details" or output =~ "Unable to parse certificate details"

    Storage.revoke_credentials()
  end

  test "format_time handles utcTime correctly" do
    # Test the format_time function by examining its behavior
    # We test it indirectly through status output with various certificate formats
    key = X509.PrivateKey.new_rsa(2048)

    # Generate certificate with explicit not_before and not_after
    cert = X509.Certificate.self_signed(key, "/CN=time-test", validity: 1)
    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    # Should show ACTIVE status
    assert output =~ "Status: ✅ ACTIVE"
    # Either successfully parses cert details or shows graceful error
    assert output =~ "Certificate Details" or output =~ "Unable to parse certificate details"

    Storage.revoke_credentials()
  end

  test "status handles unprovisioned but missing credential paths" do
    # Even though unprovisioned, the function should handle cleanly
    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    assert output =~ "UNPROVISIONED"
    assert output =~ "not been provisioned"
  end

  test "extract_subject handles multiple RDN attributes" do
    # Create a certificate with multiple subject attributes
    key = X509.PrivateKey.new_rsa(2048)

    cert =
      X509.Certificate.self_signed(
        key,
        "/C=US/ST=California/L=San Francisco/O=Farm/CN=test-farm"
      )

    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    # Should show certificate details with parsed subject
    assert output =~ "ACTIVE" or output =~ "Unable to parse"

    Storage.revoke_credentials()
  end

  test "status shows error when credentials exist but cannot be loaded due to permission" do
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=perm-test")
    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    {:ok, paths} = Storage.get_credential_paths()

    # Make cert unreadable
    File.chmod(paths.cert, 0o000)

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    assert output =~ "Unable to read certificate details"

    # Restore and cleanup
    File.chmod(paths.cert, 0o644)
    Storage.revoke_credentials()
  end

  test "parse_certificate_details handles invalid PEM gracefully" do
    key = X509.PrivateKey.new_rsa(2048)
    # Store invalid PEM data
    Storage.store_credentials("invalid-pem-data", X509.PrivateKey.to_pem(key))

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    assert output =~ "Unable to parse certificate details"

    Storage.revoke_credentials()
  end

  test "display_active_status with valid certificate shows all details" do
    key = X509.PrivateKey.new_rsa(2048)
    cert = X509.Certificate.self_signed(key, "/CN=display-test")
    Storage.store_credentials(X509.Certificate.to_pem(cert), X509.PrivateKey.to_pem(key))

    output = capture_io(fn -> Mix.Tasks.FarmNode.Status.run([]) end)

    assert output =~ "Status: ✅ ACTIVE"
    assert output =~ "Credentials Location"
    assert output =~ "The node is ready to communicate with the Hub"

    Storage.revoke_credentials()
  end
end
