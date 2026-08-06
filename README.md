# Survival Project AMP template

This GenericModule template starts the reviewed Java server from
`D:\SurvivalProject\Server` through `survivalproject-launcher.py`.

`assets/survivalproject-banner-logo.png` is the active horizontal instance
banner crop. It tightly frames and centers the Survival Project logo from the
supplied source artwork. The wider original crop remains in the template as a
non-active alternative.

The live card reads this asset from the public template repository at
`https://raw.githubusercontent.com/FrostLagoa/AMPTemplates-SurvivalProject/main/assets/survivalproject-banner-logo.png`.
No client, server binary, database data, Vault file, credential, or local
runtime artifact belongs in this repository.

The launcher accepts only a machine-DPAPI scoped Vault containing the two
shared Iris SQL keys. It passes the values to the Java child as process
environment variables and never writes them to AMP settings, command lines,
Git, or logs.

The network contract is intentional:

- `SP_BIND_ADDRESS` accepts only `127.0.0.1` (local-only) or `0.0.0.0`
  (all IPv4 interfaces). The database host remains restricted to loopback.
- Java binds login TCP `21000`, then TCP/UDP channels `21001` through `21003`.
- AMP recognizes startup only after the Java process emits the readiness line
  following successful binding of all seven listeners.
- Selecting `0.0.0.0` requires matching inbound Windows Firewall rules and,
  for Internet access, router NAT forwarding for those same ports. DNS alone
  does not publish a service.
- The template does not create a firewall rule, router NAT rule, client patch,
  or game account.

`python scripts\provision_survivalproject_runtime.py inspect` is read-only.
`runtime-vault --confirm CONFIGURE_SURVIVALPROJECT_RUNTIME_VAULT` creates the
DPAPI projection and applies the least required read/execute ACL for `NETWORK
SERVICE`. `install-template --confirm INSTALL_SURVIVALPROJECT_TEMPLATE` copies
the tracked contract to `D:\SurvivalProject\Server\amp-template`. It deliberately
does not inject an unregistered folder into ADS's deployment-template scanner:
ADS supports custom specs through a registered repository, and an arbitrary
local folder can corrupt the GenericModule cache.

