defmodule Gaia.HubWeb.PageController do
  use Gaia.HubWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
