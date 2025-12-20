defmodule Gaia.FarmNode.Device.TelemetryStreamTest do
  use ExUnit.Case, async: true

  alias Gaia.FarmNode.Device.TelemetryStream

  test "subscribe and receive broadcasts" do
    {:ok, _} = subscribe_to_test_topic()
    TelemetryStream.broadcast("test_topic", %{foo: :bar})

    assert_receive {:telemetry, "test_topic", %{foo: :bar}}, 500
  end

  test "unsubscribe should not receive messages after unsubscribing" do
    {:ok, _} = subscribe_to_test_topic()
    :ok = TelemetryStream.unsubscribe("test_topic")
    TelemetryStream.broadcast("test_topic", %{foo: :bar})

    refute_receive {:telemetry, "test_topic", %{foo: :bar}}, 500
  end

  defp subscribe_to_test_topic do
    # Ensure application is running so Registry is available
    Application.ensure_all_started(:farm_node)
    TelemetryStream.subscribe("test_topic")
  end
end
