defmodule Gaia.FarmNode.EventStreamTest do
  use ExUnit.Case, async: true

  alias Gaia.FarmNode.EventStream

  test "subscribe and receive broadcasts" do
    {:ok, _} = subscribe_to_test_topic()
    EventStream.broadcast("test_topic", %{foo: :bar})

    assert_receive {:event, "test_topic", %{foo: :bar}}, 500
  end

  test "unsubscribe should not receive messages after unsubscribing" do
    {:ok, _} = subscribe_to_test_topic()
    :ok = EventStream.unsubscribe("test_topic")
    EventStream.broadcast("test_topic", %{foo: :bar})

    refute_receive {:event, "test_topic", %{foo: :bar}}, 500
  end

  defp subscribe_to_test_topic do
    # Ensure application is running so Registry is available
    Application.ensure_all_started(:farm_node)
    EventStream.subscribe("test_topic")
  end
end
