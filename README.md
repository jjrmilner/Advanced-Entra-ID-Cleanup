# Advanced Stale Users Cleanup for Microsoft 365

A comprehensive PowerShell solution for identifying and managing inactive user accounts in Microsoft 365 environments, with enhanced guest lifecycle management and enterprise-grade safety features.

## Overview

This script addresses critical security and compliance challenges in Microsoft 365 by automatically identifying dormant accounts that represent security risks or consume unnecessary licenses. It implements a zero-trust approach for guest accounts while protecting business continuity through intelligent exclusion logic.

## Key Features

### 🛡️ Security & Compliance
- **Automated guest lifecycle**: Disable at 180 days, archive at 270 days
- **Regional compliance support**: GDPR, CCPA, and custom retention policies
- **Legal hold detection**: Protects accounts under litigation or compliance holds
- **Service principal detection**: Identifies app-accessed mailboxes to prevent false positives
- **Audit trail**: Comprehensive CSV reports for compliance documentation

### 🎯 Intelligent Detection
- **Multi-signal activity tracking**: Azure AD sign-ins, Exchange mailbox access, Teams activity
- **Smart exclusions**: Service accounts, resource mailboxes, system mailboxes
- **Guest sponsor validation**: Identifies orphaned guests with inactive sponsors
- **B2B collaboration detection**: Preserves cross-tenant collaboration accounts
- **Sensitive content protection**: Excludes guests with SharePoint/Purview access

### 🚀 Operational Safety
- **Multi-stage cleanup**: Warning → Disable → Archive workflow
- **WhatIf support**: Test changes before implementation
- **Error handling**: Graceful failure with detailed logging
- **Parallel processing**: PowerShell 7+ support for faster execution
- **Notification reports**: Ready for mail merge automation

## Prerequisites

- **PowerShell**: Version 5.1 or 7+ (7+ recommended for parallel processing)
- **Required Modules**:
  - Microsoft.Graph
  - ExchangeOnlineManagement (v3+ recommended)
- **Permissions**: See [Required Permissions](#required-permissions) section

## Installation

1. Clone or download the script:
```powershell
git clone https://github.com/jjrmilner/AdvancedStaleUsersCleanup.git
```

2. Install required modules:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Required Permissions

The script uses least-privilege principles and requests only necessary permissions:

### Read-Only Mode (Default)
- User.Read.All
- Directory.Read.All
- AuditLog.Read.All
- Group.Read.All
- Reports.Read.All (optional, for Teams activity)

### Action Mode (-Disable or -ProcessGuests)
Additional permissions:
- User.ReadWrite.All
- Group.ReadWrite.All
- GroupMember.ReadWrite.All

## Usage Examples

### Basic Report (No Changes)
```powershell
.\AdvancedStaleEntraUsersCleanup.ps1
```

### Test What Would Be Disabled
```powershell
.\AdvancedStaleEntraUsersCleanup.ps1 -Disable -WhatIf
```

### Disable Stale Members & Process Guests
```powershell
.\AdvancedStaleEntraUsersCleanup.ps1 -Disable -ProcessGuests
```

### Process Guests with Sensitive Access Protection
```powershell
.\AdvancedStaleEntraUsersCleanup.ps1 -ProcessGuests `
    -SensitiveAccessGroups @('sg-PurviewProtectedContent','sg-ConfidentialAccess')
```

### Test Mode with Limited Users
```powershell
# Process only 10 users for testing
.\AdvancedStaleEntraUsersCleanup.ps1 -MaxUsers 10 -SkipMailboxStats

# Test specific users
.\AdvancedStaleEntraUsersCleanup.ps1 -TestUserUPNs @('user1@domain.com','user2@domain.com')

# Test users with name prefix
.\AdvancedStaleEntraUsersCleanup.ps1 -TestUserFilter 'Test'
```

### Multi-Stage Cleanup with Notifications
```powershell
.\AdvancedStaleEntraUsersCleanup.ps1 -EnableMultiStageCleanup -GenerateNotifications `
    -WarningDays 30 -ProcessGuests
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `CutoffDays` | 180 | Days of inactivity before a member account is considered stale |
| `GuestCutoffDays` | 180 | Days of inactivity before a guest account is disabled |
| `GuestArchiveDays` | 270 | Days of inactivity before a guest account is archived |
| `ArchiveGroupName` | 'sg-ArchivedGuestAccounts' | Security group name for archived guests |
| `ExcludedSkuPatterns` | @('MTR*','PHONESYSTEM_VIRTUALUSER','MCOPSTN*') | License patterns to exclude |
| `SensitiveAccessGroups` | @() | Groups indicating sensitive content access |
| `ServiceAccountPatterns` | @('svc-*','service-*','app-*','sm-*') | Service account name patterns |
| `SystemMailboxPatterns` | @('Billing*','Invoice*','NoReply*','System*') | System mailbox patterns |
| `Disable` | False | Enable member account disabling |
| `ProcessGuests` | False | Enable guest lifecycle processing |
| `SkipSensitiveAccessCheck` | False | Skip SharePoint/Purview access checks |
| `CheckTeamsActivity` | False | Include Teams activity checking |
| `EnableMultiStageCleanup` | False | Use warning periods before actions |
| `GenerateNotifications` | False | Create notification reports |

## Exclusion Logic

The script implements comprehensive exclusion rules to prevent business disruption:

### Member Accounts Excluded When:
- Activity within retention period (configurable by region)
- Directory role member (admin accounts)
- Has excluded license (MTR, phone system, etc.)
- Resource mailbox (room, equipment, shared)
- Has mail forwarding or delegation
- Under litigation or compliance hold
- Mailbox accessed by service principal
- Matches service account patterns
- Mailbox statistics error (requires manual review)

### Guest Accounts Excluded When:
- Activity within guest retention period
- Invitation pending acceptance
- Already archived
- Has sensitive content access
- Active B2B collaboration account
- Guest sponsor is no longer active (flagged for review)

## Output Reports

### Main Report (StaleUsersWithExclusions_[timestamp].csv)
Comprehensive report including:
- User identification details
- All activity timestamps
- License assignments
- Exclusion reasons
- Guest-specific information
- Action recommendations

### Optional Notification Reports
- **GuestSponsorNotifications_[timestamp].csv**: For notifying sponsors about their guests
- **MemberWarnings_[timestamp].csv**: For warning users before disabling accounts

## Guest Lifecycle Management

The script implements a zero-trust approach for external users:
ne
1. **0-179 days**: Active guest period
2. **180-269 days**: Disabled (reversible)
3. **270+ days**: Archived to security group

### Guest-Specific Features:
- Sponsor validation (detects orphaned guests)
- B2B collaboration detection
- Sensitive content access protection
- Acceptance status tracking
- Multi-stage cleanup with warnings

## Safety Features

### Prevents False Positives Through:
- Multiple activity signal checks
- Service principal access detection
- Pattern matching for system accounts
- Error handling with manual review flags
- Regional compliance support

### Business Continuity Protection:
- WhatIf support for testing
- Excludes accounts with dependencies
- Respects legal/compliance holds
- Grace periods for new accounts
- Detailed logging and error reporting

## Best Practices

1. **Start with Reporting**: Run without `-Disable` to review impact
2. **Use WhatIf**: Test with `-WhatIf` before making changes
3. **Schedule Appropriately**:
   - Weekly: Report-only mode
   - Monthly: Member cleanup with `-Disable`
   - Quarterly: Guest lifecycle with `-ProcessGuests`
4. **Define Sensitive Groups**: Use `-SensitiveAccessGroups` for Purview/SharePoint protection
5. **Enable Notifications**: Use `-GenerateNotifications` for automated communications
6. **Monitor Errors**: Review accounts with mailbox statistics errors manually

## Troubleshooting

### Common Issues:

**Slow Performance**
- Use `-SkipMailboxStats` for faster testing
- Enable PowerShell 7+ for parallel processing
- Use `-MaxUsers` to process in batches

**Permission Errors**
- Ensure you have all required Graph/Exchange permissions
- Check if MFA is required for privileged operations

**Mailbox Statistics Errors**
- Common for archived or migrated mailboxes
- Script flags these for manual review
- Does not disable accounts with stat errors

---

## 📄 **License:** Apache 2.0 (see LICENSE)  
**Additional restriction:** Commons Clause (see COMMONS-CLAUSE.txt)

**SPDX headers**
- Each source file includes:  
  `SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause`

---

### FAQ: MSP and Consulting Use

**Q: Can an MSP or consultant use this tool in a paid engagement?**  
**A:** It depends on how the tool is used:  
- **Allowed:** If the tool is used internally by the end customer (e.g., installed in their tenant) and the consultant is simply assisting, this is generally acceptable.  
- **Not allowed without a commercial licence:** If the MSP or consultant provides a managed service where the tool runs in their own environment (e.g., their tenant or infrastructure) or if the value of the service substantially derives from the tool’s functionality, this falls under the definition of “Sell” in the Commons Clause and requires a commercial licence.

**Q: Why is this restricted?**  
The Commons Clause removes the right to “Sell,” which includes providing a service for a fee where the value derives from the software. This ensures fair use and prevents competitors from monetising the tool without contributing back.

**Q: How do I get a commercial licence?**  
Contact Global Micro Solutions (Pty) Ltd at:  
📧 licensing@globalmicro.co.za

## ⚠️ Warranty Disclaimer

Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Please review the Apache-2.0 WITH Commons-Clause License for the specific language governing permissions and limitations under the License.

## Author

**JJ Milner**  
Blog: https://jjrmilner.substack.com
Github: https://github.com/jjrmilner

## Contributing

Issues and suggestions welcome! Please provide:
- PowerShell version
- Error messages
- Sanitised examples of problematic accounts

## Version History

- 1.0.0 - Initial release with comprehensive stale user detection
- 2.0.0 - Added guest lifecycle management and multi-stage cleanup
- 3.0.0 - Enhanced with service principal detection and regional compliance

---

**Note**: This script makes changes to your Microsoft 365 environment. Always test thoroughly in a non-production environment first and ensure you have proper backups and rollback procedures.
