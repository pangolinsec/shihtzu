# Shihtzu
Less richly-featured than Bloodhound, Shihtzu is a lapdog for AD exploitation.  Shihtzu is intended to be a light-weight alternative to Bloodhound when stealth requirements prevent you from running full Bloodhound in an enterprise.

# Introduction:
Less richly-featured than Bloodhound, Shihtzu is a lapdog for AD exploitation.

Shihtzu is intended to be a light-weight alternative to Bloodhound when stealth requirements prevent you from running full Bloodhound in an enterprise.

Shihtzu ingests dsquery, ldapsearch, and other tool output, enriches the data, and outputs Markdown files that are readable by Obsidian. Opening up those files in Obsidian  shows relationships between users, groups, and computers, and provides insights into targetable accounts.

Shihtzu is going to continue to be updated with new features and more stability, but is a very functional POC at this stage.

# Capabilities and Features:
Shihtzu will accept dsquery output, conduct analysis to enrich the provided data, and create markdown files in a given directory. When that directory is opened with Obsidian, we can take advantage of all of Obsidian's features to conduct useful analysis of the dsquery output.

# Usage:
```
usage: shihtzu_v3_mostly-workingAppendFunction.py [-h] [-f FILE] -D DIRECTORY [--overwrite] [--append] [-G GROUPS]
                                                  [-C COMPUTERS] [-U USERS] [--logonCount LOGONCOUNT]
                                                  [--logonDate LOGONDATE]

Shihtzu parses Active Directory attributes

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  input file. Ideally .txt
  -D DIRECTORY, --directory DIRECTORY
                        Location of Obsidian Vault or subfolder for output
  --overwrite           This flag will overwrite data in folder. Defaults to not overwrite.
  --append              If set, this flag appends new data. This may result in duplicates.
  -G GROUPS, --groups GROUPS
                        input file containing groups. e.g. groups.txt
  -C COMPUTERS, --computers COMPUTERS
                        input file containing computers. e.g. computers.txt
  -U USERS, --users USERS
                        input file containing users. e.g. users.txt
  --logonCount LOGONCOUNT
                        int value for how many logons you believe indicates an active user. Default is 100
  --logonDate LOGONDATE
                        int value for how many days old a users last logon can be while still being active. Default is
                        30

```

Example:
`python3 shihtzu.py -f all.txt -D DSQUERYoutput --overwrite --logonCount 1 --logonDate 30`
This would ingest "all.txt", analyze it, and write any users, groups, and computers found to subfolders (named "USERS" "GROUPS" and "COMPUTERS") under "DSQUERYoutput". That directory should be an existing Obsidian vault.
Any users or systems that have a logoncount of 1 or less will be tagged as a badaccount due to a low logoncount.
Any users that have not logged in within the last 30 days will be tagged as a badaccount due to stale logons.

Example:
`python3 shihtzu.py -U users.txt -G groups.txt -C computers.txt -D DSQUERYoutput --append --logonCount 100 --logonDate 30`

This would ingest several files of users, groups, and computers, analyze them, and add any new data found to users, groups, and computers found to subfolders (named "USERS" "GROUPS" and "COMPUTERS") under "DSQUERYoutput".

For a given target, any new data would be also added to that target.

The assigned tags from logoncont and logondate will be changed/updated.

NOTE: The append function is more complex, and is therefore not as completely-tested as the overwrite flag.

# Requirements:
1. Python3
2. Obsidian
3. Output from DSquery or Ldapsearch or some other search that follows the format:
`<AD attributename> + <delimiter> + <attribute value>`
and where the data for different objects is separated by one or more empty lines.

For example, the following two objects, with a delimiter of "`: `", would be ingestible by Shihtzu:
```
samaccountname: Domain Admins
admincount: 1
description: Designated administrators of the domain

samaccountname: Domain Users
description: All domain users
```

## Situation-dependent Requirement:
If you are using the built-in object sorting, Shihtzu requires the `objectclass` and `operatingsystem` attributes to automatically sort objects. If you are using manual allocation with the `-U`, `-G`, and/or `-C` flags and discrete files, you do not need to collect those attributes.


# Useful Filters and Queries:
`-file:useraccount -tag:#BadAccount`
This will filter out any accounts that are tagged as "Bad" due to expired passwords, lockouts, being disabled, stale logons, or low logon count.

`-file:useraccount tag:#DelegationOpportunity`
Shows systms that have TRUSTED_FOR_DELEGATION or TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attributes

## Useful Groups:
Create the following groups and set them to easily-identifiable colors:
`path:GROUPS`
`path:COMPUTERS`
`path:USERS`

My preference is Green, Yellow, and Red respectively

# Example Output Graphs:

## Show membership flows:
This shows the graph, without orphaned nodes, showing membership paths.

![[ReadmeImage1.png]]

## Drill into users and groups:
Here, we see that Operations is a child of Business, and a parent of Finance.
Although it is not highlighted, we can also see that user01 is a member of finance (the only gotcha here is that, for groups membership flows 'downhill' and that is indicated by the directional arrows, while for users membership flows 'uphill'. This is an artifact of how linking works in Obsidian).
![[ReadmeImage2.png]]

## Highlight bad accounts:
Here, we can see that DefaultAccount, Guest, and krbtgt are all disabled or locked out accounts. They are highlighted in that light blue color because we have dragged the light blue group to the top.

Alternatively, we could simply filter out any accounts with that tag with:
`-tag:#DisabledOrLockedAccounts`
![[ReadmeImage3.png]]
