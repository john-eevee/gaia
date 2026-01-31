# Farm Onboarding Workflow

## Overview

This document describes the workflow for onboarding new farms to the Gaia cooperative. The process ensures secure provisioning of farm nodes while maintaining farmer autonomy and explicit trust principles.

## Process Flow

### 1. Admin Creates New Farm

An administrator initiates the onboarding process by calling the `add_new_farm/1` function with the following information:

- **Farm Details:**
  - Farm name
  - Business ID
  - Geographic location (required)
  - Farm boundaries (optional)

- **Farmer Details:**
  - Email address
  - First name
  - Last name
  - Role (`:owner`, `:admin`, or `:staff`)

**Example:**

```elixir
{:ok, result} = Gaia.Hub.CoopIdentity.add_new_farm(%{
  farm_name: "Green Valley Farm",
  business_id: "GVF123",
  location: %Geo.Point{coordinates: {-80.191790, 25.761680}, srid: 4326},
  farmer_email: "john@greenvalley.com",
  farmer_first_name: "John",
  farmer_last_name: "Smith",
  farmer_role: :owner
})
```

### 2. System Creates Resources

The system performs the following operations atomically:

1. **Registers the Farm** in the cooperative
2. **Creates a Data Sharing Policy** with all sharing options disabled by default (following the "share nothing" principle)
3. **Generates a Secure Provisioning Key** for the farm node
   - Single-use key
   - 30-day expiration
   - Stored as an Argon2 hash
4. **Creates a Farmer Account** with:
   - A disposable password (also stored as Argon2 hash)
   - `must_change_password` flag set to `true`

### 3. Admin Receives Credentials

The system returns the following credentials (shown only once):

```elixir
%{
  farm: %Farm{...},
  farmer: %Farmer{...},
  provisioning_key: "Tractor5-Harvest3-Field9-Wheat2-Barn7-Plow4",
  disposable_password: "Seed8-Plant2-Grow6-Reap1-Store3-Market9"
}
```

**Security Note:** These plaintext credentials are never stored and cannot be recovered. The admin must securely communicate them to the farm.

### 4. Farm Node Provisioning

The farm member uses the provisioning key to provision their farm node:

1. **Initial Connection:** The farm node connects to the Hub's provisioning endpoint (the only non-mTLS endpoint)
2. **Key Exchange:** The node presents the provisioning key
3. **Validation:** The Hub validates the key and checks:
   - Key has not been used
   - Key has not expired
4. **Certificate Issuance:** Upon successful validation:
   - The Hub's Certificate Authority generates and signs a client certificate
   - The provisioning key is marked as used (preventing reuse)
   - The certificate is returned to the farm node
5. **Future Communication:** All subsequent communication from the farm node uses mTLS with the issued certificate

### 5. Farmer First Login

When the farmer logs in for the first time:

1. **Authentication:** The farmer uses their email and the disposable password
2. **Password Change Required:** Due to `must_change_password = true`, the system prompts for a new password
3. **Password Reset:** The farmer must set a new password before accessing the system
4. **Flag Update:** Once the password is changed, `must_change_password` is set to `false`

## Security Features

### Single-Use Provisioning Keys

- Each provisioning key can only be used once
- After use, the key is marked as `used = true` in the database
- Attempts to reuse a key will be rejected

### Key Expiration

- Provisioning keys expire 30 days after generation
- Expired keys cannot be used, even if never used before
- This limits the window of opportunity for compromised keys

### Password Security

- All passwords are hashed using Argon2id before storage
- Plaintext passwords are never stored in the database
- The disposable password must be changed on first login

### Default Privacy

- All data sharing options are disabled by default
- Farmers must explicitly opt-in to share any data
- This aligns with the "share nothing" principle

## API Reference

### `add_new_farm/1`

```elixir
@spec add_new_farm(add_farm_attrs()) ::
  {:ok, add_farm_result()} | {:error, Ecto.Changeset.t()}
```

**Parameters:**

- `farm_name` (required): Name of the farm
- `business_id` (required): Business identification number
- `location` (required): GeoJSON point representing farm location
- `boundaries` (optional): GeoJSON multipolygon representing farm boundaries
- `farmer_email` (required): Email address of the farmer
- `farmer_first_name` (required): Farmer's first name
- `farmer_last_name` (required): Farmer's last name
- `farmer_role` (required): One of `:owner`, `:admin`, or `:staff`

**Returns:**

On success, returns `{:ok, result}` where result contains:

- `farm`: The created Farm struct
- `farmer`: The created Farmer struct
- `provisioning_key`: Plaintext provisioning key (shown only once)
- `disposable_password`: Plaintext disposable password (shown only once)

On error, returns `{:error, changeset}` with validation errors.

## Best Practices

### For Administrators

1. **Secure Communication:** Use a secure channel to communicate credentials to farms (encrypted email, secure messaging, or in-person)
2. **Immediate Use:** Encourage farms to use the provisioning key promptly
3. **Documentation:** Provide clear instructions to farms on using their credentials
4. **Record Keeping:** Keep a record of when farms were added (but not their credentials)

### For Farms

1. **Protect Credentials:** Keep the provisioning key and disposable password secure
2. **Prompt Setup:** Complete farm node provisioning as soon as possible
3. **Password Change:** Change the disposable password immediately upon first login
4. **Strong Password:** Use a strong, unique password for the farmer account

## Troubleshooting

### Provisioning Key Expired

If a provisioning key expires before use:

1. Contact an administrator
2. The administrator can generate a new provisioning key for the farm
3. The old key will remain expired and unusable

### Provisioning Key Lost

If the provisioning key is lost before use:

1. Contact an administrator immediately
2. The administrator should mark the current key as used to prevent misuse
3. Generate a new provisioning key for the farm

### Disposable Password Lost

If the disposable password is lost before first login:

1. Contact an administrator
2. The administrator can reset the password and generate a new disposable password
3. The farmer must use the new password and change it on first login

## Related Documentation

- [Security Architecture](../adr/security-architecture.md)
- [Certificate Authority Setup](ca-setup.md)
- [Data Sharing Policies](data-sharing-policies.md)
