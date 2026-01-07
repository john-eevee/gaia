defmodule Gaia.FarmNode.EventTest do
  use ExUnit.Case, async: true
  alias Gaia.FarmNode.Event
  import Gaia.TestingFacility.Changesets

  describe "Event.build/1" do
    test "builds a valid event from a payload map" do
      payload = %{"temperature" => 25.5, "humidity" => 80}
      changeset = Event.build(payload)

      assert changeset.valid?
      event = Ecto.Changeset.apply_changes(changeset)
      assert event.id != nil
      assert event.payload == payload

      assert(
        NaiveDateTime.compare(
          event.timestamp,
          NaiveDateTime.utc_now()
        ) == :lt
      )
    end

    test "raise on invalid data type" do
      assert_raise FunctionClauseError, fn ->
        Event.build("invalid_payload")
      end
    end
  end

  describe "Event.build/1 with changeset" do
    test "does not become an event from invalid payload" do
      data = %{temperature: 22.5, humidity: -1}
      changeset = temperature_changeset(data)
      changeset = Event.build(changeset)
      refute changeset.valid?
    end

    test "builds an event from valid payload" do
      data = %{temperature: 25, humidity: 70}
      changeset = temperature_changeset(data)
      changeset = Event.build(changeset)
      assert changeset.valid?
    end
  end

  defp temperature_changeset(data) do
    schema = %{temperature: :float, humidity: :integer}
    data = %{temperature: 22.5, humidity: 60}

    changeset =
      Ecto.Changeset.cast(
        {%{}, schema},
        data,
        Map.keys(schema)
      )
      |> Ecto.Changeset.validate_required([:temperature, :humidity])
      |> Ecto.Changeset.validate_number(:humidity, greater_than_or_equal_to: 0)
  end
end
