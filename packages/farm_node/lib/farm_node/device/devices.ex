defmodule Gaia.FarmNode.Device.TempSensor do
  @moduledoc "Temperature sensor device"
  use Gaia.Device, type: :temperature_sensor

  @impl Gaia.Device
  def generate_telemetry(_state) do
    %{
      temperature: :rand.uniform() * 20 + 5
    }
  end
end

defmodule Gaia.FarmNode.Device.PestDetector do
  @moduledoc "Pest detection device"
  use Gaia.Device, type: :pest_detector

  @impl Gaia.Device
  def generate_telemetry(_state) do
    %{
      pest_detected: :rand.uniform() < 0.1
    }
  end
end

defmodule Gaia.FarmNode.Device.MoistureSensor do
  @moduledoc "Soil moisture sensor device"
  use Gaia.Device, type: :moisture_sensor

  @impl Gaia.Device
  def generate_telemetry(_state) do
    %{
      moisture: :rand.uniform() * 100
    }
  end
end

defmodule Gaia.FarmNode.Device.GpsTracker do
  @moduledoc "GPS tracking device"
  use Gaia.Device, type: :gps_tracker

  @impl Gaia.Device
  def generate_telemetry(_state) do
    %{
      location: %{
        lat: 35.0 + :rand.uniform(),
        lon: -120.0 - :rand.uniform()
      }
    }
  end
end
