defmodule Gaia.FarmNode.Event do
  @moduledoc """
  An event is a stimuli from the environment.
  It can be originated from sensors on the field or produced by the application
  to indicate the production has reached a point in the supply chain.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  embedded_schema do
    field(:id, :string)
    field(:payload, :map)
    field(:timestamp, :naive_datetime)
  end

  def build(%Ecto.Changeset{valid?: false} = payload_changeset), do: payload_changeset

  def build(%Ecto.Changeset{valid?: true} = payload_changeset) do
    payload_changeset
    |> apply_changes()
    |> build()
  end

  def build(payload) when is_map(payload) do
    base = %{
      id: Ecto.UUID.generate(),
      timestamp: NaiveDateTime.utc_now(),
      payload: payload
    }

    changeset(base)
  end

  defp changeset(attrs) do
    %__MODULE__{}
    |> cast(attrs, [:id, :payload, :timestamp])
    |> validate_required([:id, :payload, :timestamp])
  end
end
