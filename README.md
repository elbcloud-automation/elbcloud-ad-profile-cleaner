# elbcloud-ad-profile-cleaner

Deterministic Active Directory–driven cleanup of Windows user profiles on domain-joined clients.

This project removes local Windows profiles **only** when Active Directory clearly states that the account is no longer valid. It intentionally avoids all local heuristics and time-based logic.

---

## What this tool does

A profile is deleted **only if all conditions are met**:

- The device is joined to an Active Directory domain  
- A Domain Controller is reachable via LDAP  
- The profile belongs to a **domain SID**  
- The profile is **not currently loaded**  
- The AD user is **disabled** or **does not exist**

If any of these checks fails, **nothing is deleted**.

---

## What this tool deliberately does NOT do

This tool never uses:

- `LastUseTime`
- `NTUSER.DAT` or `UsrClass.dat`
- Folder timestamps
- Guessing based on file activity
- Local Windows heuristics

These signals are unreliable in real-world Windows environments and lead to non-deterministic and unsafe behavior.

---

## Why AD-only?

Windows does not provide a trustworthy local indicator of real user activity.  
Files and registry hives are constantly touched by antivirus, indexing, system services and background maintenance.

Active Directory is the only system that provides a consistent, centrally governed source of truth about user lifecycle.

This tool enforces that truth.

---

## What is protected

This tool will **never delete**:

- Local user accounts  
- Azure AD / Entra accounts (`S-1-12-*`)  
- System accounts  
- Loaded profiles  
- Non-domain SIDs  

---

## Intended use

- Regular automated cleanup on domain-joined Windows clients  
- Removal of profiles from:
  - offboarded employees
  - deleted AD accounts
  - disabled users  

This tool is **not** intended for:
- storage optimization
- profile age cleanup
- workstation resets

Device re-provisioning should be handled by a separate lifecycle process.

---

## Safety

If no Domain Controller or LDAP connection is available, the script exits without making any changes.

This ensures that profiles are never deleted based on stale or missing AD data.

---

## Parameters

```powershell
-WhatIf    # Simulate deletions without applying changes
-LogPath  # Path to the log file
