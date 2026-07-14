# Microsoft 365 Security Tasks

These tasks require an MLFA Microsoft 365 administrator. They cannot be
completed from the Python repository alone.

## Restrict mailbox access

The worker uses Microsoft Graph application authentication. Without an
Exchange scope, application permissions such as `Mail.ReadWrite` and
`Mail.Send` can apply across the organization.

Ask an Exchange Administrator to configure **RBAC for Applications in
Exchange Online** for the automation's Microsoft Entra service principal.

The target state is:

- `Application Mail.ReadWrite` only for mailboxes managed by this hub
- `Application Mail.Send` only for mailboxes managed by this hub
- No calendar, contact, files, Teams, directory-write, or full-Exchange roles
- No duplicate unscoped Microsoft Entra mail grants that bypass the Exchange
  resource scope

Use a dedicated management scope or administrative unit containing only the
approved hub mailboxes. Test both an allowed mailbox and a mailbox outside the
scope before production use.

Microsoft's current guidance is:
https://learn.microsoft.com/exchange/permissions-exo/application-rbac

## Interactive hub login

Create a separate Microsoft Entra application for employee sign-in. Do not
reuse the background email worker's client secret for interactive login.

The sign-in application should be:

- Single-tenant (MLFA tenant only)
- Restricted to assigned MLFA users or groups
- Protected by an MLFA Conditional Access policy requiring MFA
- Configured with only OpenID Connect sign-in permissions
- Configured with the exact production redirect URL

Keep the existing magic-link login available only during migration, then
remove it after Entra sign-in and MFA have been tested.
