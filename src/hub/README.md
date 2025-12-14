# Hub

**Cooperative Intelligence & Resource Coordination**

The Hub is the central aggregation and coordination service for Gaia farming cooperatives. It collects and processes data from member farm nodes, provides advanced analytics, and coordinates shared resources and services across the cooperative

## Purpose

The Hub serves as the intelligent backbone and central authority of a farming cooperative, enabling:

- **Data Aggregation**: Consolidates telemetry and operational data from all member farms
- **Advanced Analytics**: Trend analysis, predictive modeling, and benchmarking across cooperative members
- **Resource Coordination**: Optimizes shared equipment, labor, and services across farms
- **Market Integration**: Collective pricing, supply chain coordination, and market access
- **Performance Monitoring**: Dashboards and reports on cooperative-wide metrics
- **Certificate Authority**: Provisions farm nodes with cryptographic credentials, ensuring only known and verifiable parties can access the cooperative system
- **Access Control**: Maintains security policies and validates member farm authenticity

## Architecture

The Hub is organized around several key bounded contexts:

### Aggregation Context
Responsible for collecting and normalizing data from distributed farm nodes.

**Core Concepts:**
- **FarmNode** - A connected member farm with its operational data
- **DataStream** - Incoming telemetry from farms (aggregated fields, devices, tasks)
- **Normalization** - Converting farm-specific data formats to cooperative standards

### Analytics Context
Processes aggregated data to extract insights and trends.

**Core Concepts:**
- **CropTrend** - Historical patterns across similar crops in the cooperative
- **YieldBenchmark** - Comparative yield metrics across member farms
- **ResourceUtilization** - Tracking device and service usage patterns
- **PredictiveModel** - ML models for crop forecasting and resource optimization

### Resource Coordination Context
Manages shared resources and services across the cooperative.

**Core Concepts:**
- **SharedDevice** - Equipment (drones, harvesters, etc.) available to multiple farms
- **ServiceSchedule** - Booking and scheduling of cooperative services
- **ResourceAllocation** - Fair and efficient distribution of shared resources

### Market Integration Context
Handles collective market operations and supply chain coordination.

**Core Concepts:**
- **CollectiveOffer** - Aggregated product offerings from member farms
- **MarketPrice** - Real-time pricing and market data
- **SupplyChain** - Logistics and distribution coordination

### Provisioning & Security Context
Acts as the central certificate authority for the cooperative, managing farm node onboarding and access control.

**Core Concepts:**
- **FarmMember** - Represents a legal business entity or physical farm registered in the cooperative
- **Farmer** - Human users who manage and operate farms, with specific roles (owner, admin, staff)
- **InitialProvisioningKey** - Secure, single-use key for onboarding new farm nodes
- **FarmNodeProvisioning** - Onboarding process for new member farms
- **Certificate** - Cryptographic credentials authorizing farm nodes to access the system
- **NodeRegistration** - Verification and validation of known and trustworthy parties
- **AccessControl** - Policy enforcement ensuring only authorized nodes can participate
- **CertificateLifecycle** - Issuance, renewal, and revocation of node credentials

#### Farm Member Onboarding

The Hub provides a secure onboarding workflow for adding new farm members:

1. **Admin Creates Member**: An administrator calls `CoopIdentity.add_new_farm_member/1` with farm and farmer details
2. **Automatic Setup**: The system atomically:
   - Registers the farm member
   - Creates a data sharing policy (all sharing disabled by default)
   - Generates a secure, single-use provisioning key (expires in 30 days)
   - Creates a farmer account with a disposable password
3. **Credential Distribution**: Admin receives plaintext credentials (shown only once) to securely communicate to the farm member
4. **Node Provisioning**: Farm uses the provisioning key to obtain an mTLS certificate from the Hub
5. **First Login**: Farmer logs in with disposable password and must change it immediately

For detailed information, see [Farm Member Onboarding Documentation](docs/farm-member-onboarding.md).

## Development


### Building

```bash
# From the hub directory
cd hub
mix deps.get
mix compile

# Run tests
mix test
```
## Integration with Farm Nodes

Farm nodes push data to the Hub through well-defined APIs:

- **Data Push Protocol**: Periodic submission of farm state snapshots
- **Event Stream**: Real-time event notifications for critical farm events
- **Query Interface**: Hub can query farm nodes for historical or detailed data

## Key Features (Planned)

- [ ] Multi-farm data aggregation and normalization
- [ ] Comparative yield analysis and benchmarking
- [ ] Predictive models for crop planning
- [ ] Shared device management and scheduling
- [ ] Market price aggregation and collective offers
- [ ] Performance dashboards and reporting
- [ ] Alert systems for cooperative-wide anomalies
