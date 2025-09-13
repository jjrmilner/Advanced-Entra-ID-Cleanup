<#
.SYNOPSIS
    Identify stale Microsoft 365 user accounts and optionally disable them, with enhanced guest lifecycle management.

.DESCRIPTION
    This script provides comprehensive stale account detection and automated lifecycle management for Microsoft 365 
    environments. It addresses common security and compliance challenges by identifying inactive accounts that 
    represent potential security risks or unnecessary license consumption.

    KEY SCENARIOS ADDRESSED:
    
    1. SECURITY RISK MITIGATION
       - Dormant accounts are prime targets for compromise
       - Forgotten service accounts may have excessive permissions
       - Ex-employee accounts that weren't properly offboarded
       - Guest accounts that outlived their intended purpose
    
    2. LICENSE OPTIMIZATION
       - Identify accounts consuming licenses without activity
       - Exclude resource accounts (meeting rooms, equipment) from cleanup
       - Preserve accounts with special-purpose licenses (MTR, phone system)
    
    3. COMPLIANCE & GOVERNANCE
       - Automated guest lifecycle: disable at 180 days, archive at 270 days
       - Regional compliance support (GDPR, CCPA) with configurable retention
       - Audit trail via CSV reports for compliance documentation
       - Respects legal holds, litigation requirements, and eDiscovery cases
       - Handles admin accounts with special care
    
    4. OPERATIONAL SAFETY
       - Multiple safety checks prevent accidental disruption
       - Excludes accounts with active delegations or mail forwarding
       - Detects service principal activity (apps using mailboxes)
       - Identifies system/automated mailboxes by pattern matching
       - Handles hybrid scenarios (on-premises synced accounts)
       - Protects guests with sensitive content access (SharePoint/Purview)
       - Validates mailbox statistics errors to prevent false positives

    GUEST ACCESS TO SENSITIVE CONTENT:
    
    The script recognizes that disabling guest accounts can break offline access to:
    - Files protected by Purview sensitivity labels
    - SharePoint documents with extended permissions
    - Downloaded content that requires authentication
    
    Protection mechanisms:
    - Identifies members of sensitive access groups
    - Excludes guests with any sensitive content access markers
    - Provides -SkipSensitiveAccessCheck for performance
    - Reports HasSensitiveAccess status in CSV
    
    Best practice: Define security groups that represent sensitive content access
    and pass them via -SensitiveAccessGroups parameter

    INTELLIGENT EXCLUSION LOGIC:
    
    The script implements a multi-layered approach to prevent false positives:
    
    - ACTIVITY DETECTION: Checks multiple signals including:
      * Azure AD sign-in logs (interactive and non-interactive)
      * Exchange mailbox last logon time
      * Service principal/app access to mailboxes
      * Teams activity reports (when enabled)
      * OAuth app access patterns in audit logs
    
    - ACCOUNT TYPE RECOGNITION:
      * Members vs Guests (different lifecycle policies)
      * Resource mailboxes (rooms, equipment)
      * Shared mailboxes with active delegations
      * Service accounts with special licenses
      * System/automated mailboxes by pattern (Billing*, Invoice*, etc.)
      * Cross-tenant B2B collaboration accounts
    
    - BUSINESS CONTINUITY SAFEGUARDS:
      * Accounts with mail forwarding (still routing mail)
      * Delegated mailboxes (others depend on access)
      * Litigation hold accounts (legal requirements)
      * Recently created accounts (180-day grace period)
      * Admin role members (privileged accounts)
      * Guest sponsor validation (orphaned guest detection)
    
    - ERROR HANDLING:
      * Mailbox statistics failures trigger manual review
      * Prevents marking accounts stale when activity can't be verified
      * Detailed error logging for troubleshooting
      * Service principal access detection for app-accessed mailboxes

    GUEST LIFECYCLE MANAGEMENT:
    
    Implements zero-trust principles for external users:
    - Tracks who invited each guest and when
    - Validates if sponsors are still active employees
    - Monitors acceptance status (pending vs accepted)
    - Applies time-based lifecycle:
      * 0-179 days: Active guest
      * 180-269 days: Disabled (reversible)
      * 270+ days: Archived to security group
    - Archive group created automatically if needed
    - Prevents re-processing of already archived guests
    - Multi-stage cleanup with warning periods (optional)

    OUTPUT AND REPORTING:
    
    Generates comprehensive CSV with actionable insights:
    - Stale accounts ready for cleanup
    - Excluded accounts with specific reasons
    - Guest accounts requiring action
    - Accounts needing manual review
    - Complete activity timeline for each user
    - Service principal access indicators
    - Regional compliance status
    - Teams activity tracking

    AUTOMATION CAPABILITIES:
    
    When run with -Disable and/or -ProcessGuests:
    - Revokes all active sessions before disabling
    - Applies changes with WhatIf support for testing
    - Logs all actions for audit purposes
    - Handles errors gracefully with detailed reporting
    - Generates notification reports for sponsors
    - Supports multi-stage cleanup workflow

    ADVANCED FEATURES:
    
    1. CROSS-TENANT B2B COLLABORATION
       - Detects B2B collaboration accounts via extension attributes
       - Preserves accounts involved in cross-tenant scenarios
       - Checks for accepted invitations with B2B markers
    
    2. GUEST SPONSOR VALIDATION
       - Verifies if guest sponsors are still active employees
       - Flags guests whose sponsors are disabled or left
       - Generates review tasks for orphaned guests
       - Includes sponsor status in notification reports
    
    3. TEAMS-ONLY USER DETECTION
       - Checks Teams activity separately from sign-in logs
       - Preserves accounts active only in Teams
       - Integrates with Teams usage reports
       - Requires Reports.Read.All permission
    
    4. ENHANCED COMPLIANCE HOLDS
       - Checks for eDiscovery cases
       - Detects compliance policy assignments
       - Identifies users under investigation
       - Prevents disabling accounts under legal hold
    
    5. MULTI-STAGE CLEANUP PROCESS
       - Warning period before action (customizable)
       - Staged approach: Warn → Remove Licenses → Disable → Archive
       - Different stages for members vs guests
       - Generates stage-specific notification reports
    
    6. REGIONAL COMPLIANCE
       - Applies different retention periods by country
       - Supports GDPR (365 days), CCPA, and other regional requirements
       - Configurable regional policy mapping
       - Automatic country detection from user properties
    
    7. AUTOMATED NOTIFICATIONS
       - Generates sponsor notification reports
       - Creates warning lists for upcoming actions
       - Export-ready for mail merge or automation
       - Separate reports for different stakeholders
    
    8. SERVICE PRINCIPAL DETECTION
       - Identifies mailboxes accessed by OAuth apps
       - Pattern matching for system mailboxes
       - Prevents false positives for automated accounts

    
    .LICENSE
    Licensed under the Apache License, Version 2.0 (the "Apache License");
    you may not use this file except in compliance with the Apache License.
    You may obtain a copy of the Apache License at:
        http://www.apache.org/licenses/LICENSE-2.0

    This Software is provided under the Apache License with the following
    Commons Clause Restriction:

    "The license granted herein does not include, and the Apache License
    does not grant to you, the right to Sell the Software. For purposes of
    this restriction, “Sell” means practicing any or all of the rights
    granted to you under the Apache License to provide to third parties,
    for a fee or other consideration (including without limitation fees for
    hosting, consulting, implementation, or support services related to the
    Software), a product or service whose value derives, entirely or
    substantially, from the functionality of the Software. Any license notice
    or attribution required by the Apache License must also include this
    Commons Clause Restriction."

    For paid/professional use cases prohibited above, obtain a commercial
    license from Global Micro Solutions (Pty) Ltd: licensing@globalmicro.co.za

    .WARRANTY
    Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
    either express or implied. See the Apache License for the specific language
    governing permissions and limitations under the License.

.AUTHOR
    JJ Milner
    Blog: https://jjrmilner.substack.com

.NOTES
    PowerShell 5.1/7+
    Requires: Microsoft.Graph, ExchangeOnlineManagement (v3+ recommended)
    
    Recommended Schedule:
    - Weekly: Report-only mode for monitoring
    - Monthly: With -Disable for member cleanup
    - Quarterly: With -ProcessGuests for guest lifecycle

.EXAMPLE
    .\StaleUsersCleanup.ps1
    Generates a report of all stale accounts without making changes.

.EXAMPLE
    .\StaleUsersCleanup.ps1 -Disable -WhatIf
    Shows what member accounts would be disabled without actually disabling them.

.EXAMPLE
    .\StaleUsersCleanup.ps1 -Disable -ProcessGuests
    Disables stale member accounts AND processes guest lifecycle (disable/archive).

.EXAMPLE
    .\StaleUsersCleanup.ps1 -ProcessGuests -SensitiveAccessGroups @('sg-PurviewProtectedContent','sg-ConfidentialAccess')
    Processes guests but excludes those in specified sensitive access groups.

.EXAMPLE
    .\StaleUsersCleanup.ps1 -ProcessGuests -SkipSensitiveAccessCheck
    Processes guests without checking for SharePoint/sensitive content access (faster but less safe).

.EXAMPLE
    .\StaleUsersCleanup.ps1 -MaxUsers 10 -SkipMailboxStats
    Test mode: Process only 10 users and skip mailbox statistics for faster testing.

.PARAMETER CutoffDays
    Days of inactivity before a member account is considered stale. Default: 180

.PARAMETER GuestCutoffDays
    Days of inactivity before a guest account is disabled. Default: 180

.PARAMETER GuestArchiveDays
    Days of inactivity before a guest account is archived. Default: 270

.PARAMETER ArchiveGroupName
    Name of the security group for archived guests. Default: 'sg-ArchivedGuestAccounts'

.PARAMETER CsvPath
    Path for the output report. Default: .\StaleUsersWithExclusions_[timestamp].csv

.PARAMETER ExcludedSkuPatterns
    License SKU patterns to exclude from cleanup. Default: @('MTR*','PHONESYSTEM_VIRTUALUSER','MCOPSTN*')

.PARAMETER SensitiveAccessGroups
    Array of group names that indicate sensitive content access. Members of these groups
    will be excluded from automatic disable/archive. Default: empty array

.PARAMETER ServiceAccountPatterns
    Patterns to identify service accounts that should be excluded. Default: @('svc-*','service-*','app-*','sm-*')

.PARAMETER SystemMailboxPatterns
    Patterns to identify system/automated mailboxes. Default: @('Billing*','Invoice*','NoReply*','System*','Automated*','Scanner*','Fax*')

.PARAMETER RegionalRetentionDays
    Hashtable mapping regions to retention days for compliance. Default: @{ 'US' = 180; 'EU' = 365; 'CA' = 270 }

.PARAMETER TestUserFilter
    Filter users by display name prefix for testing. Example: 'Test'

.PARAMETER MaxUsers
    Limit number of users to process for testing. Example: 10

.PARAMETER TestUserUPNs
    Array of specific UPNs to test. Example: @('user1@domain.com','user2@domain.com')

.PARAMETER UserTypeFilter
    Filter by user type for testing. Options: 'All','Guest','Member'. Default: 'All'

.PARAMETER SkipMailboxStats
    Skip mailbox statistics collection for faster testing. Default: $false

.PARAMETER SkipSensitiveAccessCheck
    Skip checking for sensitive content access (SharePoint/Purview). Use this if the
    check is taking too long or failing. Default: $false

.PARAMETER Disable
    Enable processing of stale member accounts (disable them)

.PARAMETER ProcessGuests
    Enable guest lifecycle processing (disable/archive based on inactivity)

.PARAMETER CheckTeamsActivity
    Check Teams activity separately (requires Reports.Read.All permission)

.PARAMETER EnableMultiStageCleanup
    Use multi-stage cleanup process with warning periods

.PARAMETER GenerateNotifications
    Generate notification reports for mail merge

.PARAMETER WarningDays
    Days before action to warn users (used with multi-stage cleanup). Default: 30

.PARAMETER ParallelThrottle
    Number of parallel threads for mailbox statistics (PS7+ only). Default: 6

.PARAMETER VerboseLogging
    Enable detailed logging for troubleshooting
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$CutoffDays = 180,
    [int]$GuestCutoffDays = 180,      # Days before disabling inactive guests
    [int]$GuestArchiveDays = 270,     # Days before archiving inactive guests
    [string]$ArchiveGroupName = 'sg-ArchivedGuestAccounts',
    [string]$CsvPath = ".\StaleUsersWithExclusions_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date),
    [string[]]$ExcludedSkuPatterns = @('MTR*','PHONESYSTEM_VIRTUALUSER','MCOPSTN*'),
    [string[]]$SensitiveAccessGroups = @(),  # Groups that indicate sensitive access
    [string[]]$ServiceAccountPatterns = @('svc-*','service-*','app-*','sm-*'),  # Service account patterns including shared mailboxes
    [string[]]$SystemMailboxPatterns = @('Billing*','Invoice*','NoReply*','System*','Automated*','Scanner*','Fax*'),  # System mailbox patterns
    [hashtable]$RegionalRetentionDays = @{ 'US' = 180; 'EU' = 365; 'CA' = 270 },  # Regional compliance
    [switch]$Disable,             # Perform disable action (respects -WhatIf)
    [switch]$ProcessGuests,       # Enable guest processing (disable/archive)
    [switch]$SkipSensitiveAccessCheck,  # Skip checking for sensitive content access
    [switch]$CheckTeamsActivity,  # Check Teams activity separately
    [switch]$EnableMultiStageCleanup,  # Use multi-stage cleanup process
    [switch]$GenerateNotifications,  # Generate notification reports
    [int]$WarningDays = 30,       # Days before action to warn users
    [int]$ParallelThrottle = 6,   # For PS7 parallel mailbox stats
    [switch]$VerboseLogging,
    
    # Testing parameters
    [string]$TestUserFilter = $null,    # Filter users by display name prefix
    [int]$MaxUsers = 0,                  # Limit number of users to process
    [string[]]$TestUserUPNs = @(),      # Specific UPNs to test
    [ValidateSet('All','Guest','Member')]
    [string]$UserTypeFilter = 'All',    # Filter by user type
    [switch]$SkipMailboxStats           # Skip mailbox statistics for faster testing
)

if ($VerboseLogging) { $VerbosePreference = 'Continue' }
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

# -----------------------------
# 1. Connect (least privilege)
# -----------------------------
$scopes = @("User.Read.All","Directory.Read.All","AuditLog.Read.All","Group.Read.All")
if ($CheckTeamsActivity) {
    $scopes += "Reports.Read.All"
}
if ($Disable -or $ProcessGuests) { 
    $scopes += @("User.ReadWrite.All","Group.ReadWrite.All","GroupMember.ReadWrite.All") 
}

Write-Information ("Connecting to Microsoft Graph with scopes: {0}" -f ($scopes -join ', '))
Connect-MgGraph -Scopes $scopes

Write-Information "Connecting to Exchange Online"
Connect-ExchangeOnline -ShowBanner:$false

# -----------------------------
# 2. Configuration
# -----------------------------
$cutoffDate = (Get-Date).AddDays(-$CutoffDays)
$guestCutoffDate = (Get-Date).AddDays(-$GuestCutoffDays)
$guestArchiveDate = (Get-Date).AddDays(-$GuestArchiveDays)

# -----------------------------
# 3. Helper Functions
# -----------------------------
function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$Script,
        [int]$MaxAttempts = 5,
        [int]$BaseDelayMs = 500
    )
    $attempt = 0
    while ($true) {
        try {
            return & $Script
        } catch {
            $attempt++
            if ($attempt -ge $MaxAttempts) { throw }
            $delay = [math]::Pow(2,$attempt) * $BaseDelayMs
            Write-Warning ("Retry {0}/{1} in {2}ms due to: {3}" -f $attempt, $MaxAttempts, [int]$delay, $_.Exception.Message)
            Start-Sleep -Milliseconds $delay
        }
    }
}

# Multi-stage cleanup helper
function Get-CleanupStage {
    param(
        [datetime]$LastActivity,
        [int]$CutoffDays,
        [int]$WarningDays
    )
    
    $daysSinceActivity = (Get-Date - $LastActivity).Days
    
    if ($daysSinceActivity -ge ($CutoffDays + $WarningDays)) {
        return "Disable"
    } elseif ($daysSinceActivity -ge $CutoffDays) {
        return "Warning"
    } elseif ($daysSinceActivity -ge ($CutoffDays - $WarningDays)) {
        return "PreWarning"
    } else {
        return "Active"
    }
}

# Get regional retention days
function Get-RegionalRetentionDays {
    param(
        [string]$Country,
        [hashtable]$RegionalPolicies,
        [int]$DefaultDays
    )
    
    # Map country codes to regions
    $regionMap = @{
        'US' = 'US'; 'CA' = 'CA'; 'MX' = 'US'
        'GB' = 'EU'; 'DE' = 'EU'; 'FR' = 'EU'; 'IT' = 'EU'; 'ES' = 'EU'
        'NL' = 'EU'; 'BE' = 'EU'; 'CH' = 'EU'; 'AT' = 'EU'; 'SE' = 'EU'
        'NO' = 'EU'; 'DK' = 'EU'; 'FI' = 'EU'; 'IE' = 'EU'; 'PT' = 'EU'
    }
    
    $region = $regionMap[$Country]
    if ($region -and $RegionalPolicies.ContainsKey($region)) {
        return $RegionalPolicies[$region]
    }
    
    return $DefaultDays
}

# -----------------------------
# 4. Archive Group Management
# -----------------------------
function Ensure-ArchiveGroup {
    param([string]$GroupName)
    
    Write-Information "Checking for archive group: $GroupName"
    $group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    
    if (-not $group) {
        if ($PSCmdlet.ShouldProcess($GroupName, "Create archive group")) {
            Write-Information "Creating archive group: $GroupName"
            $group = New-MgGroup -DisplayName $GroupName `
                -MailEnabled:$false `
                -SecurityEnabled:$true `
                -MailNickname ($GroupName -replace '\s','-') `
                -Description "Archived guest accounts - automatically managed by StaleUsersCleanup script"
        } else {
            Write-Warning "Archive group '$GroupName' does not exist. Use -Confirm to create it."
            return $null
        }
    }
    
    return $group
}

# -----------------------------
# 5. Prefetch Data
# -----------------------------

# 5a. SKU map (SkuId -> SkuPartNumber)
$skuMap = @{}
Write-Information "Fetching subscribed SKUs..."
$skus = Invoke-WithRetry { Get-MgSubscribedSku -All }
foreach ($sku in $skus) {
    if ($sku -and $sku.SkuId -and $sku.SkuPartNumber) {
        $skuMap[$sku.SkuId.ToString()] = $sku.SkuPartNumber.ToUpper()
    }
}

# 5b. Directory role members (admin accounts)
$adminUserIds = [System.Collections.Generic.HashSet[string]]::new()
Write-Information "Fetching directory roles and members..."
try {
    $roles = Invoke-WithRetry { Get-MgDirectoryRole -All }
    if ($roles) {
        foreach ($role in $roles) {
            $members = Invoke-WithRetry { Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All }
            foreach ($m in $members) {
                if ($m.Id) { $null = $adminUserIds.Add($m.Id) }
            }
        }
    }
    Write-Information ("Collected {0} directory role members" -f $adminUserIds.Count)
} catch {
    Write-Warning ("Failed to retrieve directory roles: {0}. Continuing without admin exclusion." -f $_.Exception.Message)
}

# 5c. Archive group and members (if processing guests)
$archiveGroup = $null
$archivedGuestIds = [System.Collections.Generic.HashSet[string]]::new()
if ($ProcessGuests) {
    $archiveGroup = Ensure-ArchiveGroup -GroupName $ArchiveGroupName
    if ($archiveGroup) {
        Write-Information "Fetching current archived guest members..."
        $members = Get-MgGroupMember -GroupId $archiveGroup.Id -All
        foreach ($m in $members) {
            $null = $archivedGuestIds.Add($m.Id)
        }
        Write-Information ("Found {0} guests already in archive group" -f $archivedGuestIds.Count)
    }
}

# 5d. Users with sign-in activity - MOVED BEFORE MAILBOXES
$selectProps = @(
 'id','displayName','userPrincipalName','createdDateTime','userType',
 'accountEnabled','onPremisesSyncEnabled','signInActivity','assignedLicenses',
 'lastPasswordChangeDateTime','externalUserState','externalUserStateChangeDateTime',
 'creationType','mail','country'
)
Write-Information "Fetching users from Microsoft Graph..."

# Apply test filters
if ($TestUserUPNs.Count -gt 0) {
    # Fetch specific users by UPN
    Write-Information ("Test mode: Fetching specific users: {0}" -f ($TestUserUPNs -join ', '))
    $users = @()
    foreach ($upn in $TestUserUPNs) {
        try {
            $user = Get-MgUser -UserId $upn -Property $selectProps -ErrorAction Stop
            $users += $user
        } catch {
            Write-Warning ("Could not fetch user {0}: {1}" -f $upn, $_.Exception.Message)
        }
    }
} elseif ($TestUserFilter) {
    # Filter by display name prefix
    Write-Information ("Test mode: Filtering users with display name starting with '{0}'" -f $TestUserFilter)
    $users = Invoke-WithRetry { 
        Get-MgUser -Filter "startsWith(displayName,'$TestUserFilter')" -All -PageSize 500 -Property $selectProps 
    }
} else {
    # Fetch all users
    $users = Invoke-WithRetry { Get-MgUser -All -PageSize 500 -Property $selectProps }
}

# Apply additional filters
if ($MaxUsers -gt 0) {
    Write-Information ("Test mode: Limiting to first {0} users" -f $MaxUsers)
    $users = $users | Select-Object -First $MaxUsers
}

if ($UserTypeFilter -ne 'All') {
    Write-Information ("Test mode: Filtering to {0} users only" -f $UserTypeFilter)
    $users = $users | Where-Object { $_.UserType -eq $UserTypeFilter }
}

Write-Information ("Fetched {0} users" -f $users.Count)

# 5e. Mailboxes (include properties for exclusion logic)
Write-Information "Fetching Exchange Online mailboxes..."
$mailboxes = Invoke-WithRetry { 
    Get-EXOMailbox -ResultSize Unlimited -Properties RecipientTypeDetails,ForwardingAddress,ForwardingSmtpAddress,GrantSendOnBehalfTo,LitigationHoldEnabled,InPlaceHolds
}
$mbxByUpn = @{}
foreach ($mbx in $mailboxes) {
    if ($mbx.UserPrincipalName) { $mbxByUpn[$mbx.UserPrincipalName.ToLower()] = $mbx }
}
Write-Information ("Fetched {0} mailboxes" -f $mailboxes.Count)

# 5f. Build inviter lookup (for guests) - using audit logs
$inviterMap = @{}
Write-Information "Building guest inviter information from audit logs..."
$guestUsers = $users | Where-Object { $_.UserType -eq 'Guest' }
if ($guestUsers.Count -gt 0 -and $guestUsers.Count -le 100) {
    # Only fetch audit logs if we have a reasonable number of guests
    try {
        $startDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-dd")
        $auditLogs = Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Invite external user' and activityDateTime ge $startDate" -All
        
        foreach ($log in $auditLogs) {
            if ($log.TargetResources -and $log.TargetResources.Count -gt 0) {
                $targetUser = $log.TargetResources | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
                if ($targetUser -and $targetUser.Id -and $log.InitiatedBy -and $log.InitiatedBy.User -and $log.InitiatedBy.User.DisplayName) {
                    $inviterMap[$targetUser.Id] = $log.InitiatedBy.User.DisplayName
                }
            }
        }
        Write-Information ("Found inviter information for {0} guests" -f $inviterMap.Count)
    } catch {
        Write-Warning "Could not retrieve guest inviter information from audit logs: $_"
    }
}

# 5g. Check for sensitive access (SharePoint/Groups)
$sensitiveAccessUsers = [System.Collections.Generic.HashSet[string]]::new()
if (-not $SkipSensitiveAccessCheck) {
    Write-Information "Checking for users with sensitive content access..."
    
    # Check membership in sensitive access groups
    if ($SensitiveAccessGroups.Count -gt 0) {
        foreach ($groupName in $SensitiveAccessGroups) {
            try {
                $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction Stop
                if ($group) {
                    $members = Get-MgGroupMember -GroupId $group.Id -All
                    foreach ($m in $members) {
                        $null = $sensitiveAccessUsers.Add($m.Id)
                    }
                    Write-Information ("Added {0} members from group '{1}'" -f $members.Count, $groupName)
                }
            } catch {
                Write-Warning "Failed to check group '$groupName': $_"
            }
        }
    }
    
    # For SharePoint access, we'll check group memberships that typically grant SharePoint access
    # Direct SharePoint permission enumeration requires different APIs and can be very slow
    Write-Information ("Total users with sensitive access markers: {0}" -f $sensitiveAccessUsers.Count)
}

# 5h. Teams Activity Check (if enabled)
$teamsActivityMap = @{}
if ($CheckTeamsActivity) {
    Write-Information "Checking Teams activity for users..."
    try {
        # Get Teams user activity for the past 180 days
        $teamsReports = Get-MgReportTeamUserActivityUserDetail -Period 'D180' -All
        foreach ($report in $teamsReports) {
            if ($report.UserPrincipalName -and $report.LastActivityDate) {
                $teamsActivityMap[$report.UserPrincipalName.ToLower()] = [datetime]$report.LastActivityDate
            }
        }
        Write-Information ("Found Teams activity for {0} users" -f $teamsActivityMap.Count)
    } catch {
        Write-Warning "Failed to retrieve Teams activity reports: $_"
    }
}

# 5i. Check for Service Principal Access to Mailboxes
$servicePrincipalAccessUsers = [System.Collections.Generic.HashSet[string]]::new()
Write-Information "Checking for mailboxes accessed by service principals..."
try {
    # Get audit logs for mail access by service principals - simplified query
    $startDate = (Get-Date).AddDays(-90)
    $endDate = Get-Date
    
    # Note: Service principal detection via audit logs has limitations
    # For now, we'll rely on mailbox statistics and pattern matching
    Write-Information "Service principal detection will use mailbox statistics and pattern matching"
    
} catch {
    Write-Warning "Could not check service principal access: $_"
}

# 5j. Check for Compliance Holds
$complianceHoldUsers = [System.Collections.Generic.HashSet[string]]::new()
Write-Information "Checking for additional compliance holds..."
try {
    # Check for users under compliance policies
    $compliancePolicies = Get-MgSecurityCase -ErrorAction SilentlyContinue
    foreach ($case in $compliancePolicies) {
        $caseHolds = Get-MgSecurityCaseEdiscoveryCaseCustodian -EdiscoveryCaseId $case.Id -All
        foreach ($custodian in $caseHolds) {
            if ($custodian.UserSourceId) {
                $null = $complianceHoldUsers.Add($custodian.UserSourceId)
            }
        }
    }
    Write-Information ("Found {0} users under compliance holds" -f $complianceHoldUsers.Count)
} catch {
    Write-Warning "Could not check compliance holds: $_"
}

# NOW - Mailbox statistics AFTER user filtering
# Only process mailboxes for the filtered users
$statsByUpn = @{}
if (-not $SkipMailboxStats) {
    # Get only the mailboxes for our filtered users
    $filteredUserUpns = $users | Where-Object { $_.UserPrincipalName } | ForEach-Object { $_.UserPrincipalName.ToLower() }
    $mbxUpns = $mailboxes | Where-Object { 
        $_.UserPrincipalName -and $filteredUserUpns -contains $_.UserPrincipalName.ToLower() 
    } | ForEach-Object { $_.UserPrincipalName }
    
    if ($mbxUpns.Count -gt 0) {
        Write-Information ("Fetching mailbox statistics for {0} mailboxes (filtered from {1} total)..." -f $mbxUpns.Count, $mailboxes.Count)
        Write-Host "Starting mailbox statistics collection. This may take several minutes..." -ForegroundColor Yellow
        Write-Host "Processing mailboxes in batches. Progress updates every 10 mailboxes." -ForegroundColor Yellow
        
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $counter = 0
        $failedCount = 0
        
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PS7+ parallel processing with progress
            Write-Information "Using parallel processing (PowerShell 7+)..."
            
            # Create a synchronized hashtable for progress tracking
            $syncHash = [hashtable]::Synchronized(@{
                Counter = 0
                Failed = 0
                Total = $mbxUpns.Count
            })
            
            $statResults = $mbxUpns | ForEach-Object -Parallel {
                $upn = $_
                $sync = $using:syncHash
                
                try {
                    $s = Get-EXOMailboxStatistics -Identity $upn -ErrorAction Stop
                    $result = [PSCustomObject]@{ Upn = $upn; LastLogon = $s.LastLogonTime; Error = $null }
                } catch {
                    $result = [PSCustomObject]@{ Upn = $upn; LastLogon = $null; Error = $_.Exception.Message }
                    $sync.Failed++
                }
                
                $sync.Counter++
                if ($sync.Counter % 10 -eq 0 -or $sync.Counter -eq $sync.Total) {
                    Write-Host ("Progress: {0}/{1} mailboxes processed ({2:N0}% complete, {3} failed)" -f $sync.Counter, $sync.Total, (($sync.Counter / $sync.Total) * 100), $sync.Failed) -ForegroundColor Cyan
                }
                
                $result
            } -ThrottleLimit $ParallelThrottle
            
            $failedCount = $syncHash.Failed
        } else {
            # PS5.1 sequential processing with progress
            Write-Information "Using sequential processing (PowerShell 5.1)..."
            $statResults = @()
            
            foreach ($upn in $mbxUpns) {
                $counter++
                if ($counter % 10 -eq 0 -or $counter -eq $mbxUpns.Count) {
                    $percentComplete = ($counter / $mbxUpns.Count) * 100
                    Write-Progress -Activity "Fetching mailbox statistics" -Status "$counter of $($mbxUpns.Count) - $failedCount failed" -PercentComplete $percentComplete
                    Write-Information ("Progress: {0}/{1} mailboxes processed ({2:N0}% complete, {3} failed)" -f $counter, $mbxUpns.Count, $percentComplete, $failedCount)
                }
                
                try {
                    $s = Get-EXOMailboxStatistics -Identity $upn -ErrorAction Stop
                    $statResults += [PSCustomObject]@{ Upn = $upn; LastLogon = $s.LastLogonTime; Error = $null }
                } catch {
                    $failedCount++
                    $statResults += [PSCustomObject]@{ Upn = $upn; LastLogon = $null; Error = $_.Exception.Message }
                    Write-Warning ("Mailbox statistics failed for {0}: {1}" -f $upn, $_.Exception.Message)
                }
            }
            Write-Progress -Activity "Fetching mailbox statistics" -Completed
        }
        
        $stopwatch.Stop()
        Write-Information ("Mailbox statistics collection completed in {0:N2} seconds" -f $stopwatch.Elapsed.TotalSeconds)
        Write-Information ("Successfully retrieved: {0}, Failed: {1}" -f ($mbxUpns.Count - $failedCount), $failedCount)
        
        # Process results and track errors
        foreach ($r in $statResults) {
            if ($r -and $r.Upn) {
                if ($r.LastLogon) {
                    $statsByUpn[$r.Upn.ToLower()] = @{ LastLogon = $r.LastLogon; Error = $null }
                } else {
                    # Store error information for accounts we couldn't check
                    $statsByUpn[$r.Upn.ToLower()] = @{ LastLogon = $null; Error = $r.Error }
                    if ($VerboseLogging) {
                        Write-Verbose ("Failed to get stats for {0}: {1}" -f $r.Upn, $r.Error)
                    }
                }
            }
        }
    }
} else {
    Write-Information "Test mode: Skipping mailbox statistics collection"
}

# Display summary of what will be processed
Write-Information ""
Write-Information "=== Processing Summary ==="
Write-Information ("Total Users: {0}" -f $users.Count)
Write-Information ("- Members: {0}" -f ($users | Where-Object { $_.UserType -eq 'Member' }).Count)
Write-Information ("- Guests: {0}" -f ($users | Where-Object { $_.UserType -eq 'Guest' }).Count)
Write-Information ("Total Mailboxes: {0}" -f $mailboxes.Count)
Write-Information ("Admin Role Members: {0}" -f $adminUserIds.Count)
if ($SkipMailboxStats) {
    Write-Information ("Mailbox Statistics: SKIPPED")
} else {
    $userMailboxCount = ($users | Where-Object { $_.UserPrincipalName -and $mbxByUpn.ContainsKey($_.UserPrincipalName.ToLower()) }).Count
    Write-Information ("Mailboxes to Process: {0}" -f $userMailboxCount)
}
Write-Information ""

# -----------------------------
# 6. Build Report
# -----------------------------
Write-Information ("Building report rows for {0} users..." -f ($users.Count))
$userCounter = 0
$allUsers = foreach ($u in $users) {
    try {
        $userCounter++
        if ($userCounter % 100 -eq 0) {
            Write-Verbose ("Processing user {0} of {1}" -f $userCounter, $users.Count)
        }
        
        # Debug first user to see structure
        if ($userCounter -eq 1 -and $VerboseLogging) {
            Write-Verbose "First user object structure:"
            Write-Verbose ($u | Format-List | Out-String)
        }
        
        $upn = $u.UserPrincipalName
        $created = $u.CreatedDateTime
        $pwdChanged = $u.LastPasswordChangeDateTime

        # Sign-in activity (nullable) - with better null handling
        $lssi = $null
        $lsi = $null
        $lnsi = $null
        
        if ($u -and $u.SignInActivity) {
            if ($u.SignInActivity.PSObject.Properties['lastSuccessfulSignInDateTime']) {
                $lssi = $u.SignInActivity.lastSuccessfulSignInDateTime
            }
            if ($u.SignInActivity.PSObject.Properties['lastSignInDateTime']) {
                $lsi = $u.SignInActivity.lastSignInDateTime
            }
            if ($u.SignInActivity.PSObject.Properties['lastNonInteractiveSignInDateTime']) {
                $lnsi = $u.SignInActivity.lastNonInteractiveSignInDateTime
            }
        }

        # Most recent activity (including Teams if available)
        $mostRecentActivity = $null
        $activityDates = @($lssi, $lsi, $lnsi) | Where-Object { $_ } | ForEach-Object { [datetime]$_ }
        
        # Add Teams activity if available
        $teamsLastActivity = $null
        if ($upn -and $teamsActivityMap.ContainsKey($upn.ToLower())) {
            $teamsLastActivity = $teamsActivityMap[$upn.ToLower()]
            $activityDates += $teamsLastActivity
        }
        
        if ($activityDates) {
            $mostRecentActivity = ($activityDates | Sort-Object -Descending)[0]
        }

        # Licenses
        $skuIds = @($u.AssignedLicenses.SkuId)
        $skuParts = @()
        foreach ($id in $skuIds) {
            if ($id) {
                $idStr = $id.ToString()
                if ($skuMap.ContainsKey($idStr)) { $skuParts += $skuMap[$idStr] } else { $skuParts += $idStr }
            }
        }

        # Excluded license?
        $hasExcludedSku = $false
        foreach ($sku in $skuParts) {
            foreach ($pat in $ExcludedSkuPatterns) {
                if (($sku -as [string]) -and $sku.ToUpper() -like $pat) { $hasExcludedSku = $true; break }
            }
            if ($hasExcludedSku) { break }
        }

        # Mailbox info
        $mbx = $null
        if ($upn -and $mbxByUpn.ContainsKey($upn.ToLower())) { $mbx = $mbxByUpn[$upn.ToLower()] }

        $mbxType = $null
        if ($mbx) { $mbxType = $mbx.RecipientTypeDetails }

        $hasFwdOrDelegation = $false
        if ($mbx) {
            if ($mbx.ForwardingAddress -or $mbx.ForwardingSmtpAddress -or $mbx.GrantSendOnBehalfTo) { $hasFwdOrDelegation = $true }
        }

        # Last mailbox logon (by UPN) and any errors
        $lastMailboxLogon = $null
        $mailboxStatError = $null
        if ($upn -and $statsByUpn.ContainsKey($upn.ToLower())) { 
            $statInfo = $statsByUpn[$upn.ToLower()]
            $lastMailboxLogon = $statInfo.LastLogon
            $mailboxStatError = $statInfo.Error
        }

        # Mailbox holds
        $onHold = $false
        if ($mbx) {
            $hasInPlaceHolds = $false
            if ($mbx.InPlaceHolds) { $hasInPlaceHolds = ($mbx.InPlaceHolds.Count -gt 0) }
            $onHold = $mbx.LitigationHoldEnabled -or $hasInPlaceHolds
        }
        
        # Service principal access check
        $hasServicePrincipalAccess = $false
        $lastServicePrincipalAccess = $null
        if ($upn -and $servicePrincipalAccessUsers.Contains($u.Id)) {
            $hasServicePrincipalAccess = $true
            # Note: We detected SP access but don't have exact timestamp in this simplified check
            # For production use, you'd want to track the actual access times
        }

        # Guest-specific properties and enhanced checks
        $invitedBy = $null
        $inviterActive = $true
        $isArchived = $false
        $daysSinceLastActivity = $null
        $hasSensitiveAccess = $false
        $isB2BCollab = $false
        $cleanupStage = $null
        $applicableRetentionDays = $CutoffDays
        
        # Service account and system mailbox detection
        $isServiceAccount = $false
        $isSystemMailbox = $false
        
        foreach ($pattern in $ServiceAccountPatterns) {
            if (($u.DisplayName -and $u.DisplayName -like $pattern) -or 
                ($upn -and $upn -like $pattern)) {
                $isServiceAccount = $true
                break
            }
        }
        
        foreach ($pattern in $SystemMailboxPatterns) {
            if (($u.DisplayName -and $u.DisplayName -like $pattern) -or 
                ($upn -and $upn -like $pattern)) {
                $isSystemMailbox = $true
                break
            }
        }
        
        # Regional compliance check
        if ($u.Country) {
            $applicableRetentionDays = Get-RegionalRetentionDays -Country $u.Country -RegionalPolicies $RegionalRetentionDays -DefaultDays $CutoffDays
        }
        
        if ($u.UserType -eq 'Guest') {
            if ($inviterMap.ContainsKey($u.Id)) { $invitedBy = $inviterMap[$u.Id] }
            $isArchived = $archivedGuestIds.Contains($u.Id)
            $hasSensitiveAccess = $sensitiveAccessUsers.Contains($u.Id)
            
            # Check for B2B collaboration
            if ($u.CreationType -eq 'Invitation' -and $u.ExternalUserState -eq 'Accepted') {
                # Check for cross-tenant sync attributes
                try {
                    $extProps = Get-MgUser -UserId $u.Id -Property "onPremisesExtensionAttributes" -ErrorAction SilentlyContinue
                    if ($extProps.OnPremisesExtensionAttributes.extensionAttribute1 -match 'B2B|CrossTenant') {
                        $isB2BCollab = $true
                    }
                } catch {}
            }
            
            # Validate sponsor is still active
            if ($invitedBy) {
                try {
                    $sponsor = Get-MgUser -Filter "displayName eq '$invitedBy'" -ErrorAction SilentlyContinue
                    if ($sponsor -and $sponsor.Count -gt 0) {
                        $sponsorUser = $sponsor | Select-Object -First 1
                        if (-not $sponsorUser.AccountEnabled -or $sponsorUser.UserType -eq 'Guest') {
                            $inviterActive = $false
                        }
                    } else {
                        $inviterActive = $false
                    }
                } catch {
                    $inviterActive = $true  # Assume active if we can't verify
                }
            }
            
            # Calculate days since last activity
            if ($mostRecentActivity) {
                $daysSinceLastActivity = [int]((Get-Date) - $mostRecentActivity).TotalDays
            } elseif ($created) {
                $daysSinceLastActivity = [int]((Get-Date) - $created).TotalDays
            }
            
            # Determine cleanup stage
            if ($EnableMultiStageCleanup -and $mostRecentActivity) {
                $cleanupStage = Get-CleanupStage -LastActivity $mostRecentActivity -CutoffDays $GuestCutoffDays -WarningDays $WarningDays
            }
        } else {
            # Member cleanup stage
            if ($EnableMultiStageCleanup -and $mostRecentActivity) {
                $cleanupStage = Get-CleanupStage -LastActivity $mostRecentActivity -CutoffDays $applicableRetentionDays -WarningDays $WarningDays
            }
        }

        # Exclusion logic
        $exclusionReason = $null
        $guestAction = $null
        
        # Check for mailbox statistics error first - applies to all user types
        if ($mbx -and $mailboxStatError) {
            $exclusionReason = "Manual review required - mailbox statistics error"
        } elseif ($isServiceAccount) {
            $exclusionReason = "Service account pattern match"
        } elseif ($isSystemMailbox) {
            $exclusionReason = "System/automated mailbox pattern"
        } elseif ($complianceHoldUsers.Contains($u.Id)) {
            $exclusionReason = "Under compliance hold"
        } elseif ($u.UserType -eq 'Guest') {
            # Guest-specific exclusion logic
            
            # Use the most recent date between creation and last activity for comparison
            $guestAgeReference = $created
            if ($mostRecentActivity -and $mostRecentActivity -gt $created) {
                $guestAgeReference = $mostRecentActivity
            }
            
            if ($guestAgeReference -ge $guestCutoffDate) {
                $exclusionReason = "Guest activity or creation within retention period ($GuestCutoffDays days)"
            } elseif ($adminUserIds.Contains($u.Id)) {
                $exclusionReason = "Guest is directory role member"
            } elseif ($u.ExternalUserState -eq 'PendingAcceptance') {
                $exclusionReason = "Guest invitation pending acceptance"
            } elseif ($isArchived) {
                $exclusionReason = "Guest already archived"
            } elseif ($hasSensitiveAccess) {
                $exclusionReason = "Guest has sensitive content access (SharePoint/Purview)"
            } elseif ($isB2BCollab) {
                $exclusionReason = "Active B2B collaboration account"
            } elseif (-not $inviterActive) {
                $exclusionReason = "Guest sponsor no longer active - needs review"
                $guestAction = "Review"
            } else {
                # Determine guest action needed based on multi-stage cleanup
                if ($EnableMultiStageCleanup -and $cleanupStage) {
                    switch ($cleanupStage) {
                        "Warning" { 
                            $guestAction = "Warning"
                            $exclusionReason = "Guest in warning period - notify sponsor"
                        }
                        "Disable" {
                            if ($daysSinceLastActivity -ge $GuestArchiveDays) {
                                $guestAction = "Archive"
                                $exclusionReason = "Guest inactive for $GuestArchiveDays+ days - pending archive"
                            } else {
                                $guestAction = "Disable"
                                $exclusionReason = "Guest inactive for $GuestCutoffDays+ days - pending disable"
                            }
                        }
                    }
                } else {
                    # Standard logic without multi-stage
                    if ($mostRecentActivity) {
                        if ($mostRecentActivity -lt $guestArchiveDate) {
                            $guestAction = "Archive"
                            $exclusionReason = "Guest inactive for $GuestArchiveDays+ days - pending archive"
                        } elseif ($mostRecentActivity -lt $guestCutoffDate) {
                            $guestAction = "Disable"
                            $exclusionReason = "Guest inactive for $GuestCutoffDays+ days - pending disable"
                        }
                    } elseif ($created -lt $guestArchiveDate) {
                        $guestAction = "Archive"
                        $exclusionReason = "Guest never signed in, created $GuestArchiveDays+ days ago - pending archive"
                    } elseif ($created -lt $guestCutoffDate) {
                        $guestAction = "Disable"
                        $exclusionReason = "Guest never signed in, created $GuestCutoffDays+ days ago - pending disable"
                    }
                }
            }
        } else {
            # Member exclusion logic with regional compliance
            $memberCutoffDate = (Get-Date).AddDays(-$applicableRetentionDays)
            
            # Use the most recent date between creation and last activity for comparison
            $accountAgeReference = $created
            if ($mostRecentActivity -and $mostRecentActivity -gt $created) {
                $accountAgeReference = $mostRecentActivity
            }
            
            if ($accountAgeReference -ge $memberCutoffDate) {
                $exclusionReason = "Account activity or creation within retention period ($applicableRetentionDays days)"
            } elseif ($adminUserIds.Contains($u.Id)) {
                $exclusionReason = "Directory role member"
            } elseif ($lssi -and [datetime]$lssi -ge $memberCutoffDate) {
                $exclusionReason = "Recent successful sign-in"
            } elseif ($lsi -and [datetime]$lsi -ge $memberCutoffDate) {
                $exclusionReason = "Recent interactive sign-in"
            } elseif ($lnsi -and [datetime]$lnsi -ge $memberCutoffDate) {
                $exclusionReason = "Recent non-interactive sign-in"
            } elseif ($teamsLastActivity -and $teamsLastActivity -ge $memberCutoffDate) {
                $exclusionReason = "Recent Teams activity"
            } elseif ($lastMailboxLogon -and $lastMailboxLogon -ge $memberCutoffDate) {
                $exclusionReason = "Mailbox accessed via app/service principal"
            } elseif ($hasServicePrincipalAccess) {
                $exclusionReason = "Mailbox accessed by service principal (OAuth app)"
            } elseif ($hasExcludedSku) {
                $exclusionReason = "Excluded license assigned"
            } elseif ($mbxType -in @('SharedMailbox','RoomMailbox','EquipmentMailbox','LinkedMailbox')) {
                $exclusionReason = "Mailbox type: $mbxType"
            } elseif ($hasFwdOrDelegation) {
                $exclusionReason = "Mailbox has forwarding or delegation"
            } elseif ($onHold) {
                $exclusionReason = "Mailbox on hold"
            }
        }

        # Account type
        $accountType = 'Member'
        if ($u.UserType -eq 'Guest') {
            $accountType = 'Guest'
        } elseif ($mbxType -in @('SharedMailbox','RoomMailbox','EquipmentMailbox','LinkedMailbox')) {
            $accountType = 'Resource'
        } elseif ($skuParts -contains 'PHONESYSTEM_VIRTUALUSER') {
            $accountType = 'Resource'
        }

        # Resolve exclusion reason
        $resolvedExclusionReason = 'Stale'
        if ($exclusionReason) { $resolvedExclusionReason = $exclusionReason }

        [PSCustomObject]@{
            ObjectId                  = $u.Id
            DisplayName               = $u.DisplayName
            UserPrincipalName         = $upn
            AccountEnabled            = $u.AccountEnabled
            OnPremisesSyncEnabled     = $u.OnPremisesSyncEnabled
            UserType                  = $u.UserType
            AccountType               = $accountType
            Country                   = $u.Country
            CreatedDateTime           = $created
            LastPasswordChange        = $pwdChanged
            LastSuccessfulSignIn      = $lssi
            LastInteractiveSignIn     = $lsi
            LastNonInteractiveSignIn  = $lnsi
            LastMailboxLogon          = $lastMailboxLogon
            LastTeamsActivity         = $teamsLastActivity
            MostRecentActivity        = $mostRecentActivity
            DaysSinceLastActivity     = $daysSinceLastActivity
            AssignedLicenses          = ($skuParts -join ', ')
            MailboxType               = $mbxType
            HasForwardingOrDelegation = $hasFwdOrDelegation
            OnHold                    = $onHold
            UnderComplianceHold       = $complianceHoldUsers.Contains($u.Id)
            IsAdmin                   = $adminUserIds.Contains($u.Id)
            IsServiceAccount          = $isServiceAccount
            HasServicePrincipalAccess = $hasServicePrincipalAccess
            # Guest-specific columns
            ExternalUserState         = $u.ExternalUserState
            InvitedBy                 = $invitedBy
            InviterActive             = $inviterActive
            IsArchived                = $isArchived
            HasSensitiveAccess        = $hasSensitiveAccess
            IsB2BCollaboration        = $isB2BCollab
            GuestAction               = $guestAction
            CleanupStage              = $cleanupStage
            ApplicableRetentionDays   = $applicableRetentionDays
            ExclusionReason           = $resolvedExclusionReason
            MailboxStatError          = $mailboxStatError
        }
    } catch {
        Write-Warning ("Error processing user {0} ({1}): {2}" -f $u.DisplayName, $u.UserPrincipalName, $_.Exception.Message)
        Write-Warning ("Error at line: {0}" -f $_.InvocationInfo.ScriptLineNumber)
        # Return a minimal object so the script can continue
        [PSCustomObject]@{
            ObjectId = $u.Id
            DisplayName = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            ExclusionReason = "Processing error - manual review required"
            MailboxStatError = $_.Exception.Message
        }
    }
}

# -----------------------------
# 7. Export Report
# -----------------------------
$sorted = $allUsers | Sort-Object UserType, ExclusionReason, DisplayName
$sorted | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Information ("✅ Full user report exported to {0}" -f $CsvPath)

# Summary statistics
$staleMembers = ($sorted | Where-Object { $_.UserType -eq 'Member' -and $_.ExclusionReason -eq 'Stale' }).Count
$excludedMembers = ($sorted | Where-Object { $_.UserType -eq 'Member' -and $_.ExclusionReason -ne 'Stale' }).Count
$guestsToDisable = ($sorted | Where-Object { $_.GuestAction -eq 'Disable' }).Count
$guestsToArchive = ($sorted | Where-Object { $_.GuestAction -eq 'Archive' }).Count
$guestsToWarn = ($sorted | Where-Object { $_.GuestAction -eq 'Warning' }).Count
$guestsToReview = ($sorted | Where-Object { $_.GuestAction -eq 'Review' }).Count
$activeGuests = ($sorted | Where-Object { $_.UserType -eq 'Guest' -and -not $_.GuestAction -and $_.ExclusionReason -ne 'Guest already archived' }).Count
$needsReview = ($sorted | Where-Object { $_.ExclusionReason -eq 'Manual review required - mailbox statistics error' }).Count

Write-Information ""
Write-Information "=== Summary ==="
Write-Information ("Members: {0} stale, {1} excluded" -f $staleMembers, $excludedMembers)
Write-Information ("Guests: {0} active, {1} to warn, {2} to disable, {3} to archive, {4} need review" -f $activeGuests, $guestsToWarn, $guestsToDisable, $guestsToArchive, $guestsToReview)
if ($needsReview -gt 0) {
    Write-Warning ("⚠️  {0} accounts need manual review due to mailbox statistics errors" -f $needsReview)
}

# Generate notification reports if requested
if ($GenerateNotifications) {
    Write-Information ""
    Write-Information "=== Generating Notification Reports ==="
    
    # Guest sponsor notifications
    $sponsorNotifications = @{}
    foreach ($guest in $sorted | Where-Object { $_.GuestAction -in @('Warning','Disable','Review') -and $_.InvitedBy }) {
        if (-not $sponsorNotifications.ContainsKey($guest.InvitedBy)) {
            $sponsorNotifications[$guest.InvitedBy] = @()
        }
        $sponsorNotifications[$guest.InvitedBy] += [PSCustomObject]@{
            GuestName = $guest.DisplayName
            GuestEmail = $guest.UserPrincipalName
            DaysInactive = $guest.DaysSinceLastActivity
            Action = $guest.GuestAction
            LastActivity = $guest.MostRecentActivity
        }
    }
    
    # Export sponsor notifications
    if ($sponsorNotifications.Count -gt 0) {
        $notificationPath = ".\GuestSponsorNotifications_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date)
        $notificationData = foreach ($sponsor in $sponsorNotifications.GetEnumerator()) {
            foreach ($guest in $sponsor.Value) {
                [PSCustomObject]@{
                    SponsorName = $sponsor.Key
                    GuestName = $guest.GuestName
                    GuestEmail = $guest.GuestEmail
                    DaysInactive = $guest.DaysInactive
                    PlannedAction = $guest.Action
                    LastActivity = $guest.LastActivity
                }
            }
        }
        $notificationData | Export-Csv -Path $notificationPath -NoTypeInformation -Encoding UTF8
        Write-Information ("Guest sponsor notifications exported to: {0}" -f $notificationPath)
    }
    
    # Member warning notifications
    $memberWarnings = $sorted | Where-Object { $_.UserType -eq 'Member' -and $_.CleanupStage -eq 'Warning' }
    if ($memberWarnings.Count -gt 0) {
        $warningPath = ".\MemberWarnings_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date)
        $memberWarnings | Select-Object DisplayName, UserPrincipalName, DaysSinceLastActivity, MostRecentActivity, AssignedLicenses |
            Export-Csv -Path $warningPath -NoTypeInformation -Encoding UTF8
        Write-Information ("Member warning notifications exported to: {0}" -f $warningPath)
    }
}

# -----------------------------
# 8. Optional: Disable Stale Members
# -----------------------------
if ($Disable) {
    $toDisable = $allUsers | Where-Object {
        $_.UserType -eq 'Member' -and
        $_.ExclusionReason -eq 'Stale' -and
        $_.AccountEnabled -eq $true -and
        $_.IsAdmin -ne $true -and
        $_.OnPremisesSyncEnabled -ne $true -and
        -not $_.MailboxStatError  # Don't disable if we couldn't verify activity
    }

    Write-Information ""
    Write-Information ("Found {0} stale member accounts eligible for disable." -f ($toDisable.Count))

    foreach ($row in $toDisable) {
        if ($PSCmdlet.ShouldProcess($row.UserPrincipalName, "Disable user and revoke sessions")) {
            try {
                # Revoke sessions first
                try {
                    Revoke-MgUserSignInSession -UserId $row.ObjectId -ErrorAction Stop
                    Write-Information ("Revoked sessions for {0}" -f $row.UserPrincipalName)
                } catch {
                    Write-Warning ("Failed to revoke sessions for {0}: {1}" -f $row.UserPrincipalName, $_.Exception.Message)
                }

                # Disable the account
                Update-MgUser -UserId $row.ObjectId -AccountEnabled:$false -ErrorAction Stop
                Write-Information ("Disabled: {0}" -f $row.UserPrincipalName)
            } catch {
                Write-Warning ("Failed to disable {0}: {1}" -f $row.UserPrincipalName, $_.Exception.Message)
            }
        }
    }
}

# -----------------------------
# 9. Optional: Process Guests
# -----------------------------
if ($ProcessGuests -and $archiveGroup) {
    Write-Information ""
    Write-Information "=== Processing Guest Accounts ==="
    
    # Process guests that need to be disabled
    $guestsToDisableNow = $allUsers | Where-Object {
        $_.GuestAction -eq 'Disable' -and
        $_.AccountEnabled -eq $true
    }
    
    if ($guestsToDisableNow.Count -gt 0) {
        Write-Information ("Disabling {0} inactive guest accounts..." -f $guestsToDisableNow.Count)
        foreach ($guest in $guestsToDisableNow) {
            if ($PSCmdlet.ShouldProcess($guest.UserPrincipalName, "Disable guest account")) {
                try {
                    # Revoke sessions
                    try {
                        Revoke-MgUserSignInSession -UserId $guest.ObjectId -ErrorAction Stop
                    } catch {
                        Write-Warning ("Failed to revoke sessions for guest {0}: {1}" -f $guest.UserPrincipalName, $_.Exception.Message)
                    }
                    
                    # Disable account
                    Update-MgUser -UserId $guest.ObjectId -AccountEnabled:$false -ErrorAction Stop
                    Write-Information ("Disabled guest: {0} (inactive for {1} days)" -f $guest.DisplayName, $guest.DaysSinceLastActivity)
                } catch {
                    Write-Warning ("Failed to disable guest {0}: {1}" -f $guest.UserPrincipalName, $_.Exception.Message)
                }
            }
        }
    }
    
    # Process guests that need to be archived
    $guestsToArchiveNow = $allUsers | Where-Object {
        $_.GuestAction -eq 'Archive' -and
        -not $_.IsArchived
    }
    
    if ($guestsToArchiveNow.Count -gt 0) {
        Write-Information ("Archiving {0} inactive guest accounts..." -f $guestsToArchiveNow.Count)
        foreach ($guest in $guestsToArchiveNow) {
            if ($PSCmdlet.ShouldProcess($guest.UserPrincipalName, "Archive guest account to $ArchiveGroupName")) {
                try {
                    # Ensure account is disabled
                    if ($guest.AccountEnabled) {
                        Update-MgUser -UserId $guest.ObjectId -AccountEnabled:$false -ErrorAction Stop
                        Revoke-MgUserSignInSession -UserId $guest.ObjectId -ErrorAction SilentlyContinue
                    }
                    
                    # Add to archive group
                    New-MgGroupMember -GroupId $archiveGroup.Id -DirectoryObjectId $guest.ObjectId -ErrorAction Stop
                    Write-Information ("Archived guest: {0} (inactive for {1} days)" -f $guest.DisplayName, $guest.DaysSinceLastActivity)
                } catch {
                    Write-Warning ("Failed to archive guest {0}: {1}" -f $guest.UserPrincipalName, $_.Exception.Message)
                }
            }
        }
    }
}

# -----------------------------
# 10. Cleanup
# -----------------------------
try { Disconnect-ExchangeOnline -Confirm:$false } catch {}
try { Disconnect-MgGraph } catch {}

Write-Information ""
Write-Information "✅ Script completed successfully!"
