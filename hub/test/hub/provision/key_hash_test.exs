defmodule Gaia.Hub.Provision.KeyHash.ArgonTest do
  use ExUnit.Case

  alias Gaia.Hub.Provision.KeyHash.Argon

  describe "hash/1" do
    test "returns a binary hash for a valid key" do
      key = "test_key"
      hash = Argon.hash(key)
      assert is_binary(hash)
      assert hash != key
      # Argon2 hashes start with $argon2
      assert String.starts_with?(hash, "$argon2")
    end

    test "produces different hashes for the same key due to salt" do
      key = "test_key"
      hash1 = Argon.hash(key)
      hash2 = Argon.hash(key)
      assert hash1 != hash2
    end

    test "raises FunctionClauseError for non-binary input" do
      assert_raise FunctionClauseError, fn ->
        Argon.hash(123)
      end
    end
  end

  describe "verify/2" do
    test "returns true when provided password matches the expected hash" do
      key = "correct_password"
      hash = Argon.hash(key)
      assert Argon.verify(hash, key) == true
    end

    test "returns false when provided password does not match the expected hash" do
      key = "correct_password"
      wrong_key = "wrong_password"
      hash = Argon.hash(key)
      assert Argon.verify(hash, wrong_key) == false
    end

    test "returns false when expected hash is invalid" do
      key = "password"
      invalid_hash = "invalid_hash"
      assert Argon.verify(invalid_hash, key) == false
    end

    test "raises FunctionClauseError for non-binary inputs" do
      hash = Argon.hash("password")

      assert_raise FunctionClauseError, fn ->
        Argon.verify(hash, 123)
      end

      assert_raise FunctionClauseError, fn ->
        Argon.verify(hash, 123)
      end
    end
  end
end
