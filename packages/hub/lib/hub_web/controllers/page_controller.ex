defmodule Gaia.HubWeb.PageController do
  use HubWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
