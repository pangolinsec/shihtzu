#!/usr/bin/env python3
"""
Shihtzu - Active Directory Parser for Obsidian

This tool parses Active Directory attributes from LDAP search results and
converts them to markdown files compatible with Obsidian.
"""

import argparse
import collections
from datetime import datetime, timedelta
import enum
import logging
import os
from pathlib import Path
import pickle
import re
from typing import Dict, List, Optional, Set, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('shihtzu')

# Constants
DEFAULT_LOGON_COUNT_THRESHOLD = 100
DEFAULT_LOGON_DATE_THRESHOLD = 30
DEFAULT_FILENAME_SEED = "cn"
DEFAULT_DELIMITER = ": "
DEFAULT_SEPARATOR = "--------------------"

# Headers for markdown files
HEADERS = {
    'rawdata': '# Raw Data:',
    'tags': '# Tags:',
    'time': '# Clean Timestamps:',
    'members': '# Members:',
    'parents': '# Parents:',
    'uac-calculated': '# UserAccountControl Values:',
    'userdefined': '# User Defined:',
    'domain': '# Domain:',
    'creds': '# Creds:'
}

# UserAccountControl attribute mapping
UAC_ATTRIBUTES = [
    "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION", 
    "ADS_UF_PASSWORD_EXPIRED", 
    "ADS_UF_DONT_REQUIRE_PREAUTH", 
    "ADS_UF_USE_DES_KEY_ONLY", 
    "ADS_UF_NOT_DELEGATED", 
    "ADS_UF_TRUSTED_FOR_DELEGATION", 
    "ADS_UF_SMARTCARD_REQUIRED", 
    "ADS_UF_MNS_LOGON_ACCOUNT", 
    "ADS_UF_DONT_EXPIRE_PASSWD", 
    "N/A", "N/A", 
    "ADS_UF_SERVER_TRUST_ACCOUNT", 
    "ADS_UF_WORKSTATION_TRUST_ACCOUNT", 
    "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT", 
    "ADS_UF_NORMAL_ACCOUNT", 
    "ADS_UF_TEMP_DUPLICATE_ACCOUNT", 
    "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED", 
    "ADS_UF_PASSWD_CANT_CHANGE", 
    "ADS_UF_PASSWD_NOTREQD", 
    "ADS_UF_LOCKOUT", 
    "ADS_UF_HOMEDIR_REQUIRED", 
    "ADS_UF_ACCOUNTDISABLE", 
    "ADS_UF_SCRIPT"
]

UAC_VALUES = [
    1000000, 800000, 400000, 200000, 100000, 80000, 40000, 20000, 10000,
    8000, 4000, 2000, 1000, 800, 200, 100, 80, 40, 20, 10, 8, 2, 1
]


class ADObjectType(enum.Enum):
    """Enum for AD object types"""
    USER = 1
    GROUP = 2
    COMPUTER = 3
    DOMAIN = 4
    UNKNOWN = 5


class ADObject:
    """Class representing an Active Directory object"""
    
    def __init__(self, filename_seed: str = DEFAULT_FILENAME_SEED):
        """Initialize a new AD object
        
        Args:
            filename_seed: Attribute to use for filename generation
        """
        self.raw_data = collections.defaultdict(list)
        self.tags = []
        self.members = []
        self.time_values = []
        self.parents = []
        self.uac_values = []
        self.domain = []
        self.creds = []
        self.admincount = []
        self.groupsid = []
        self.primarygroup = []
        self.userdefined = []
        self.description = []
        self.object_type = ADObjectType.UNKNOWN
        self.filename_seed = filename_seed
        
    def add_attribute(self, name: str, value: str) -> None:
        """Add a raw attribute value
        
        Args:
            name: Attribute name
            value: Attribute value
        """
        self.raw_data[name.lower()].append(value)
        
    def get_filename(self) -> str:
        """Get the filename for this object
        
        Returns:
            Filename string based on the filename_seed attribute
        """
        if self.filename_seed in self.raw_data and self.raw_data[self.filename_seed]:
            return self.raw_data[self.filename_seed][0]
        return "unknown"
    
    def determine_type(self, source_file_hint: Optional[str] = None) -> None:
        """Determine the type of this AD object
        
        Args:
            source_file_hint: Optional hint about the source file type
        """
        if self._is_group(source_file_hint):
            self.object_type = ADObjectType.GROUP
        elif self._is_computer(source_file_hint):
            self.object_type = ADObjectType.COMPUTER
        else:
            self.object_type = ADObjectType.USER
    
    def _is_group(self, file_hint: Optional[str] = None) -> bool:
        """Check if this object is a group
        
        Args:
            file_hint: Optional file type hint
            
        Returns:
            True if this is a group object
        """
        if 'objectclass' in self.raw_data:
            return any('group' in val.lower() for val in self.raw_data['objectclass'])
        return file_hint == "groupsFile"
    
    def _is_computer(self, file_hint: Optional[str] = None) -> bool:
        """Check if this object is a computer
        
        Args:
            file_hint: Optional file type hint
            
        Returns:
            True if this is a computer object
        """
        if 'objectclass' in self.raw_data:
            is_computer_class = any('computer' in val.lower() for val in self.raw_data['objectclass'])
            has_os = 'operatingsystem' in self.raw_data
            return is_computer_class and has_os
        return file_hint == "computersFile"
    
    def process_members(self) -> None:
        """Process member attributes"""
        if 'member' in self.raw_data:
            for mem in self.raw_data['member']:
                clean_members = get_common_name_from_dn(mem)
                for member in clean_members:
                    if member not in self.members:
                        self.members.append(member)
    
    def process_parents(self) -> None:
        """Process memberOf attributes"""
        if 'memberof' in self.raw_data:
            for parent in self.raw_data['memberof']:
                clean_parents = get_common_name_from_dn(parent)
                for parent in clean_parents:
                    if parent not in self.parents:
                        self.parents.append(parent)
    
    def process_logon_count(self, threshold: int) -> None:
        """Process logon count and add tags if below threshold
        
        Args:
            threshold: Minimum acceptable logon count
        """
        if 'logoncount' in self.raw_data and self.raw_data['logoncount']:
            try:
                logon_count = int(self.raw_data['logoncount'][0])
                if logon_count < threshold:
                    self.tags.append('#BadAccount due to #LowLogonCount at this Domain Controller')
            except ValueError:
                logger.warning(f"Invalid logon count value: {self.raw_data['logoncount'][0]}")
    
    def process_time_values(self, date_threshold: int) -> None:
        """Process time values and convert to readable format
        
        Args:
            date_threshold: Maximum days since last logon
        """
        time_attrs = ['pwdlastset', 'badpasswordtime', 'lastlogon', 'lastlogontimestamp']
        now = datetime.utcnow()
        cutoff_date = now - timedelta(days=date_threshold)
        
        for attr in time_attrs:
            if attr in self.raw_data and self.raw_data[attr]:
                value = self.raw_data[attr][0]
                
                # Check if the value is a Windows timestamp (numeric)
                if value.isdigit():
                    win_time = int(value)
                    if win_time != 0:
                        clean_time = datetime.fromtimestamp(get_unix_time(win_time))
                        converted_time = str(clean_time)
                        self.time_values.append(f"{attr}{DEFAULT_DELIMITER}{converted_time}")
                        
                        # Tag accounts with stale logons
                        if attr in ['lastlogon', 'lastlogontimestamp'] and clean_time < cutoff_date:
                            if attr == 'lastlogon':
                                self.tags.append("#BadAccount due to #StaleLogons at this Domain Controller")
                            else:
                                self.tags.append("#BadAccount due to #StaleLogons replicated across the Domain. "
                                                "See info on 'lastlogontimestamp' attribute for more information.")
    
    def process_uac_values(self) -> None:
        """Process UserAccountControl values"""
        if 'useraccountcontrol' in self.raw_data and self.raw_data['useraccountcontrol']:
            try:
                uac_val = self.raw_data['useraccountcontrol'][0]
                attributes = calculate_uac_attributes(int(uac_val))
                
                for attr in attributes:
                    self.uac_values.append(f"[[UserAccountControlValues#{attr}]]")
                
                # Add tags based on UAC attributes
                if "ADS_UF_SMARTCARD_REQUIRED" in attributes:
                    self.tags.append("#SmartcardRequired")
                if "ADS_UF_LOCKOUT" in attributes or "ADS_UF_ACCOUNTDISABLE" in attributes:
                    self.tags.append('#BadAccount due to #DisabledOrLockedAccount at this Domain Controller')
                if "ADS_UF_PASSWORD_EXPIRED" in attributes:
                    self.tags.append('#BadAccount because #PasswordExpired at this Domain Controller')
                if "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION" in attributes or "ADS_UF_TRUSTED_FOR_DELEGATION" in attributes:
                    self.tags.append('#DelegationOpportunity')
                if "ADS_UF_NORMAL_ACCOUNT" in attributes:
                    self.tags.append('#NormalAccount')
                if "ADS_UF_SERVER_TRUST_ACCOUNT" in attributes:
                    self.tags.append("#ServerTrustAccount")
            except ValueError:
                logger.warning(f"Invalid UAC value: {self.raw_data['useraccountcontrol'][0]}")
    
    def process_credentials(self) -> None:
        """Process credential attributes"""
        if 'userpassword' in self.raw_data and self.raw_data['userpassword']:
            self.tags.append("#Creds because of #UserPasswordAttribute. This is a #HighImportance finding!")
    
    def process_all(self, logon_count_threshold: int, logon_date_threshold: int,
                  source_file_hint: Optional[str] = None) -> None:
        """Process all attributes and determine object type
        
        Args:
            logon_count_threshold: Minimum acceptable logon count
            logon_date_threshold: Maximum days since last logon
            source_file_hint: Optional hint about the source file
        """
        self.process_members()
        self.process_parents()
        self.process_logon_count(logon_count_threshold)
        self.process_time_values(logon_date_threshold)
        self.process_uac_values()
        self.process_credentials()
        self.determine_type(source_file_hint)
    
    def to_markdown(self, output_dir: str, overwrite: bool = False, append: bool = False) -> str:
        """Write this object to a markdown file
        
        Args:
            output_dir: Directory to write the file to
            overwrite: Whether to overwrite existing files
            append: Whether to append to existing files
        
        Returns:
            String describing the action taken: 'created', 'overwritten', 'appended', or 'skipped'
        """
        filename = self.get_filename()
        if not filename:
            logger.warning(f"Object has no valid filename attribute: {self.raw_data}")
            return 'skipped'
        
        filepath = os.path.join(output_dir, f"{filename}.md")
        
        # Check if file exists
        if os.path.exists(filepath):
            if append:
                try:
                    # Smart append - only add new data
                    return self._smart_append(filepath)
                except Exception as e:
                    logger.error(f"Error during smart append: {e}")
                    logger.warning("Falling back to regular append")
                    
                    # Fall back to regular append
                    with open(filepath, 'a') as f:
                        f.write("\n\n## Appended Data - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
                        self._write_content(f)
                    return 'appended'
                
            elif overwrite:
                # File exists and overwrite is enabled
                with open(filepath, 'w') as f:
                    self._write_content(f)
                return 'overwritten'
            else:
                logger.warning(f"File already exists and neither overwrite nor append is enabled: {filepath}")
                return 'skipped'
        
        # File doesn't exist
        with open(filepath, 'w') as f:
            self._write_content(f)
        
        return 'created'

    def _smart_append(self, filepath: str) -> str:
        """Intelligently append only new data to an existing file
        
        Args:
            filepath: Path to the file to append to
            
        Returns:
            String describing the action taken
        """
        # Read existing file content
        with open(filepath, 'r') as f:
            existing_content = f.read()
        
        # Parse existing content to identify what's already there
        existing_data = self._parse_existing_file(existing_content)
        
        # Track what data we'll be adding
        new_data = {
            'raw_data': {},
            'tags': [],
            'members': [],
            'parents': [],
            'uac_values': [],
            'time_values': [],
            'userdefined': []
        }
        
        # Find new raw data attributes
        for key, values in self.raw_data.items():
            if key not in existing_data['raw_data']:
                # This is a completely new attribute
                new_data['raw_data'][key] = values
            else:
                # Check for new values for this attribute
                new_values = []
                for value in values:
                    if value not in existing_data['raw_data'][key]:
                        new_values.append(value)
                
                if new_values:
                    new_data['raw_data'][key] = new_values
        
        # Find new tags, members, parents, etc.
        for item in self.tags:
            if item not in existing_data['tags']:
                #print('existing')
                #print(existing_data['tags'])
                #print('new')
                #print(new_data['tags'])
                #print()
                new_data['tags'].append(item)
        
        for item in self.members:
            if item not in existing_data['members']:
                new_data['members'].append(item)
        
        for item in self.parents:
            if item not in existing_data['parents']:
                new_data['parents'].append(item)
        
        for item in self.uac_values:
            if item not in existing_data['uac_values']:
                new_data['uac_values'].append(item)
        
        for item in self.time_values:
            # Extract attribute name from "attr: value" format
            attr_name = item.split(DEFAULT_DELIMITER)[0] if DEFAULT_DELIMITER in item else item
            # Check if this timestamp exists in the existing data
            if not any(entry.startswith(attr_name + DEFAULT_DELIMITER) for entry in existing_data['time_values']):
                new_data['time_values'].append(item)
        
        for item in self.userdefined:
            if item not in existing_data['userdefined']:
                new_data['userdefined'].append(item)
        
        # Check if we have any new data to add
        has_new_data = (
            bool(new_data['raw_data']) or 
            bool(new_data['tags']) or 
            bool(new_data['members']) or 
            bool(new_data['parents']) or 
            bool(new_data['uac_values']) or 
            bool(new_data['time_values']) or 
            bool(new_data['userdefined'])
        )
        
        if not has_new_data:
            logger.info(f"No new data to append to {filepath}")
            return 'unchanged'
        
        # We have new data, so append it to the file
        with open(filepath, 'a') as f:
            f.write("\n\n## New Data Added - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
            
            # Write new raw data if any
            if new_data['raw_data']:
                f.write(f"{HEADERS['rawdata']} (New Attributes)\n")
                f.write("```plaintext raw\n")
                for key, values in new_data['raw_data'].items():
                    for value in values:
                        f.write(f"{key}{DEFAULT_DELIMITER}{value}\n")
                f.write("```\n")
            
            # Write new tags if any
            if new_data['tags']:
                f.write(f"\n{HEADERS['tags']} (New Tags)\n")
                f.write('\n'.join(new_data['tags']) + '\n')
            
            # Write new members if any
            if new_data['members']:
                f.write(f"\n{HEADERS['members']} (New Members)\n")
                linked_members = [create_link(member) for member in new_data['members']]
                f.write('\n'.join(linked_members) + '\n')
            
            # Write new parents if any
            if new_data['parents']:
                f.write(f"\n{HEADERS['parents']} (New Parents)\n")
                linked_parents = [create_link(parent) for parent in new_data['parents']]
                f.write('\n'.join(linked_parents) + '\n')
            
            # Write new UAC values if any
            if new_data['uac_values']:
                f.write(f"\n{HEADERS['uac-calculated']} (New Values)\n")
                f.write('\n'.join(new_data['uac_values']) + '\n')
            
            # Write new time values if any
            if new_data['time_values']:
                f.write(f"\n{HEADERS['time']} (New Values)\n")
                f.write('\n'.join(new_data['time_values']) + '\n')
            
            # Write new user defined values if any
            if new_data['userdefined']:
                f.write(f"\n{HEADERS['userdefined']} (New Values)\n")
                f.write('\n'.join(new_data['userdefined']) + '\n')
        
        return 'appended'

    def _parse_existing_file(self, content: str) -> dict:
        """Parse an existing markdown file to extract its data
        
        Args:
            content: The file content as a string
            
        Returns:
            Dictionary with parsed data
        """
        result = {
            'raw_data': {},
            'tags': [],
            'members': [],
            'parents': [],
            'uac_values': [],
            'time_values': [],
            'userdefined': []
        }
        
        # Extract raw data
        raw_data_match = re.search(r'# Raw Data:\s*```plaintext raw\s*(.*?)\s*```', content, re.DOTALL)
        if raw_data_match:
            raw_data_text = raw_data_match.group(1)
            for line in raw_data_text.strip().split('\n'):
                if DEFAULT_DELIMITER in line:
                    key, value = line.split(DEFAULT_DELIMITER, 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key not in result['raw_data']:
                        result['raw_data'][key] = []
                    
                    result['raw_data'][key].append(value)
        
        # Extract tags
        tags_match = re.search(r'# Tags:\s*(.*?)(?=\n# |\Z)', content, re.DOTALL)
        if tags_match:
            tags_text = tags_match.group(1)
            for line in tags_text.strip().split('\n'):
                if line.strip():
                    result['tags'].append(line.strip())
        
        # Extract members
        members_match = re.search(r'# Members:\s*(.*?)(?=\n#|\Z)', content, re.DOTALL)
        if members_match:
            members_text = members_match.group(1)
            for line in members_text.strip().split('\n'):
                if line.strip():
                    # Remove [[ and ]] from links
                    member = line.strip().replace('[[', '').replace(']]', '')
                    result['members'].append(member)
        
        # Extract parents
        parents_match = re.search(r'# Parents:\s*(.*?)(?=\n#|\Z)', content, re.DOTALL)
        if parents_match:
            parents_text = parents_match.group(1)
            for line in parents_text.strip().split('\n'):
                if line.strip():
                    # Remove [[ and ]] from links
                    parent = line.strip().replace('[[', '').replace(']]', '')
                    result['parents'].append(parent)
        
        # Extract UAC values
        uac_match = re.search(r'# UserAccountControl Values:\s*(.*?)(?=\n#|\Z)', content, re.DOTALL)
        if uac_match:
            uac_text = uac_match.group(1)
            for line in uac_text.strip().split('\n'):
                if line.strip():
                    result['uac_values'].append(line.strip())
        
        # Extract time values
        time_match = re.search(r'# Clean Timestamps:\s*(.*?)(?=\n#|\Z)', content, re.DOTALL)
        if time_match:
            time_text = time_match.group(1)
            for line in time_text.strip().split('\n'):
                if line.strip():
                    result['time_values'].append(line.strip())
        
        # Extract user defined values
        userdefined_match = re.search(r'# User Defined:\s*(.*?)(?=\n#|\Z)', content, re.DOTALL)
        if userdefined_match:
            userdefined_text = userdefined_match.group(1)
            for line in userdefined_text.strip().split('\n'):
                if line.strip():
                    result['userdefined'].append(line.strip())
        
        return result

    def _write_content(self, f):
        """Write the content to the file
        
        Args:
            f: File object to write to
        """
        # Write raw data
        f.write(f"{HEADERS['rawdata']}\n")
        f.write("```plaintext raw\n")
        for key, values in self.raw_data.items():
            for value in values:
                f.write(f"{key}{DEFAULT_DELIMITER}{value}\n")
        f.write("```\n")
        
        # Write tags
        if self.tags:
            f.write(f"\n{HEADERS['tags']}\n")
            f.write('\n'.join(self.tags) + '\n')
        
        # Write members
        if self.members:
            f.write(f"\n{HEADERS['members']}\n")
            linked_members = [create_link(member) for member in self.members]
            f.write('\n'.join(linked_members) + '\n')
        
        # Write parents
        if self.parents:
            f.write(f"\n{HEADERS['parents']}\n")
            linked_parents = [create_link(parent) for parent in self.parents]
            f.write('\n'.join(linked_parents) + '\n')
        
        # Write UAC values
        if self.uac_values:
            f.write(f"\n{HEADERS['uac-calculated']}\n")
            f.write('\n'.join(self.uac_values) + '\n')
        
        # Write time values
        if self.time_values:
            f.write(f"\n{HEADERS['time']}\n")
            f.write('\n'.join(self.time_values) + '\n')
        
        # Write user defined section
        f.write(f"\n{HEADERS['userdefined']}\n")
        if self.userdefined:
            f.write('\n'.join(self.userdefined) + '\n')
    


class ADCollection:
    """Collection of AD objects by type"""
    
    def __init__(self, base_dir: str):
        """Initialize an AD collection
        
        Args:
            base_dir: Base directory for output
        """
        self.users = {}
        self.groups = {}
        self.computers = {}
        self.domains = {}
        self.base_dir = base_dir
        self.user_dir = os.path.join(base_dir, "USERS")
        self.group_dir = os.path.join(base_dir, "GROUPS")
        self.computer_dir = os.path.join(base_dir, "COMPUTERS")
        self.domain_dir = os.path.join(base_dir, "DOMAINS")
    
    def add_object(self, ad_object: ADObject) -> None:
        """Add an object to the appropriate collection
        
        Args:
            ad_object: AD object to add
        """
        key = ad_object.get_filename()
        if not key:
            logger.warning("Object has no valid key, skipping")
            return
            
        if ad_object.object_type == ADObjectType.USER:
            self.users[key] = ad_object
        elif ad_object.object_type == ADObjectType.GROUP:
            self.groups[key] = ad_object
        elif ad_object.object_type == ADObjectType.COMPUTER:
            self.computers[key] = ad_object
        elif ad_object.object_type == ADObjectType.DOMAIN:
            self.domains[key] = ad_object
    
    def create_output_dirs(self) -> None:
        """Create output directories if they don't exist"""
        dirs = {
            "USERS": self.user_dir,
            "GROUPS": self.group_dir,
            "COMPUTERS": self.computer_dir,
            "DOMAINS": self.domain_dir
        }
        
        for name, path in dirs.items():
            if name == "USERS" and self.users or \
               name == "GROUPS" and self.groups or \
               name == "COMPUTERS" and self.computers or \
               name == "DOMAINS" and self.domains:
                if not os.path.exists(path):
                    os.makedirs(path)
                    logger.info(f"Created directory: {path}")
                else:
                    logger.info(f"Using existing directory: {path}")
    
    def write_all(self, overwrite: bool = False, append: bool = False) -> None:
        """Write all objects to markdown files
        
        Args:
            overwrite: Whether to overwrite existing files
            append: Whether to append to existing files
        """
        self.create_output_dirs()
        
        # Process admin privileges first
        self._process_admin_privileges()
        
        # Track statistics
        stats = {
            'created': 0,
            'overwritten': 0,
            'appended': 0,
            'skipped': 0
        }
        
        def process_result(result):
            if result in stats:
                stats[result] += 1
        
        for key, obj in self.users.items():
            result = obj.to_markdown(self.user_dir, overwrite, append)
            process_result(result)
        
        for key, obj in self.groups.items():
            result = obj.to_markdown(self.group_dir, overwrite, append)
            process_result(result)
            
        for key, obj in self.computers.items():
            result = obj.to_markdown(self.computer_dir, overwrite, append)
            process_result(result)
            
        for key, obj in self.domains.items():
            result = obj.to_markdown(self.domain_dir, overwrite, append)
            process_result(result)
            
        # Log statistics
        logger.info(f"File operation statistics:")
        logger.info(f"  Created: {stats['created']}")
        logger.info(f"  Overwritten: {stats['overwritten']}")
        logger.info(f"  Appended: {stats['appended']}")
        logger.info(f"  Skipped: {stats['skipped']}")
    
    def _process_admin_privileges(self) -> None:
        """Process admin privileges based on admincount attribute"""
        # Find groups with admincount=1
        admin_groups = []
        for key, group in self.groups.items():
            if 'admincount' in group.raw_data and group.raw_data['admincount']:
                if group.raw_data['admincount'][0] != '0':
                    admin_groups.append(key)
                    
        # Tag these groups and their members recursively
        for group_name in admin_groups:
            self._tag_as_admin(group_name, group_name)
    
    def _tag_as_admin(self, group_name: str, origin_name: str) -> None:
        """Recursively tag a group and its members as admin
        
        Args:
            group_name: Name of the group to tag
            origin_name: Name of the original admin group
        """
        if group_name in self.groups:
            group = self.groups[group_name]
            tag = f"#GroupIsAdmin based on native admincount=1"
            if tag not in group.tags:
                group.tags.append(tag)
            
            # Process each member
            for member in group.members:
                # If member is a group
                if member in self.groups:
                    child_group = self.groups[member]
                    tag = f"#GroupIsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in {origin_name}"
                    if tag not in child_group.tags:
                        child_group.tags.append(tag)
                    self._tag_as_admin(member, origin_name)
                
                # If member is a user
                if member in self.users:
                    user = self.users[member]
                    tag = f"#IsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in {origin_name}"
                    if tag not in user.tags:
                        user.tags.append(tag)
                
                # If member is a computer
                if member in self.computers:
                    computer = self.computers[member]
                    tag = f"#ComputerIsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in {origin_name}"
                    if tag not in computer.tags:
                        computer.tags.append(tag)


def get_unix_time(windows_time: int) -> float:
    """Convert Windows filetime to Unix timestamp
    
    Args:
        windows_time: Windows filetime (100-nanosecond intervals since January 1, 1601)
        
    Returns:
        Unix timestamp (seconds since January 1, 1970)
    """
    # Windows epoch starts at 1601-01-01
    # Unix epoch starts at 1970-01-01
    # The difference is 116444736000000000 100-nanosecond intervals
    windows_time -= 116444736000000000
    # Convert 100-nanosecond intervals to seconds
    return windows_time / 10000000


def calculate_uac_attributes(uac_value: int) -> List[str]:
    """Calculate UserAccountControl attributes from a numeric value
    
    Args:
        uac_value: Numeric UAC value
        
    Returns:
        List of UAC attribute names
    """
    # Convert to hex and remove '0x' prefix
    hex_val = int(hex(uac_value)[2:])
    attributes = []
    
    # Iterate through the attribute values
    while hex_val > 0:
        for i, value in enumerate(UAC_VALUES):
            if hex_val >= value:
                attributes.append(UAC_ATTRIBUTES[i])
                hex_val -= value
                break
    
    return attributes


def get_common_name_from_dn(distinguished_name: str) -> List[str]:
    """Extract common names from a distinguished name
    
    Args:
        distinguished_name: Distinguished Name string
        
    Returns:
        List of extracted common names
    """
    names = []
    dn_parts = distinguished_name.split(', ')
    
    for part in dn_parts:
        part = part.upper().split(",OU=")[0]
        part = part.upper().split(",CN=")[0]
        if part.upper().startswith("CN="):
            part = part[3:]  # Remove CN= prefix
            names.append(part)
    
    return names


def create_link(name: str) -> str:
    """Create an Obsidian link for a name
    
    Args:
        name: Name to link to
        
    Returns:
        Formatted link string
    """
    return f"[[{name}]]"


def create_uac_link(attribute: str) -> str:
    """Create an Obsidian link for a UAC attribute
    
    Args:
        attribute: UAC attribute name
        
    Returns:
        Formatted link string
    """
    return f"[[UserAccountControlValues#{attribute}]]"


def parse_ad_file(file_path: str, filename_seed: str, delimiter: str,
                logon_count_threshold: int, logon_date_threshold: int,
                file_hint: Optional[str] = None) -> List[ADObject]:
    """Parse an AD file and return a list of objects
    
    Args:
        file_path: Path to the file to parse
        filename_seed: Attribute to use for object filenames
        delimiter: Delimiter between attribute names and values
        logon_count_threshold: Threshold for logon counts
        logon_date_threshold: Threshold for logon dates
        file_hint: Optional hint about the file type
        
    Returns:
        List of parsed AD objects
    """
    objects = []
    current_object = None
    
    logger.info(f"Parsing file: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    line = line.strip()
                    
                    # Skip empty lines at the beginning
                    if not line and not current_object:
                        continue
                    
                    # Handle backslashes
                    if "\\" in line:
                        line = line.replace('\\', '')
                    
                    # Split by delimiter
                    parts = line.split(delimiter, 1)
                    
                    if len(parts) == 2:
                        # This is an attribute line
                        if not current_object:
                            current_object = ADObject(filename_seed)
                        
                        attr_name, attr_value = parts
                        current_object.add_attribute(attr_name.strip(), attr_value.strip())
                    elif (len(parts) == 1 and not parts[0] and current_object) or (len(parts) == 1 and parts[0] == DEFAULT_SEPARATOR and current_object):
                        # Empty line or separator line - end of object
                        current_object.process_all(logon_count_threshold, logon_date_threshold, file_hint)
                        objects.append(current_object)
                        current_object = None
                    
                    elif len(parts) != 1:
                        logger.warning(f"Malformed line {line_num} in {file_path}: {line}")
                
                except Exception as e:
                    logger.error(f"Error processing line {line_num} in {file_path}: {e}")
            
            # Don't forget the last object
            if current_object:
                current_object.process_all(logon_count_threshold, logon_date_threshold, file_hint)
                objects.append(current_object)
    
    except Exception as e:
        logger.error(f"Error parsing file {file_path}: {e}")
    
    logger.info(f"Parsed {len(objects)} objects from {file_path}")
    return objects


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Shihtzu parses Active Directory attributes")
    
    # Input options
    parser.add_argument("-f", "--file", help="input file. Ideally .txt", required=False)
    parser.add_argument("-G", "--groups", help="input file containing groups. e.g. groups.txt", required=False)
    parser.add_argument("-C", "--computers", help="input file containing computers. e.g. computers.txt", required=False)
    parser.add_argument("-U", "--users", help="input file containing users. e.g. users.txt", required=False)
    
    # Output options
    parser.add_argument("-D", "--directory", help="Location of Obsidian Vault or subfolder for output", required=True)
    #parser.add_argument("--overwrite", action="store_true", help="This flag will overwrite data in folder. Defaults to not overwrite.")
    #parser.add_argument("--append", action="store_true", help="If set, this flag appends new data. This may result in duplicates.")
    
    # Configuration options
    parser.add_argument("--logonCount", type=int, help=f"int value for how many logons you believe indicates an active user. Default is {DEFAULT_LOGON_COUNT_THRESHOLD}")
    parser.add_argument("--logonDate", type=int, help=f"int value for how many days old a users last logon can be while still being active. Default is {DEFAULT_LOGON_DATE_THRESHOLD}")
    parser.add_argument("--filenameSeed", help=f"Attribute to use for filename generation. Default is {DEFAULT_FILENAME_SEED}")
    parser.add_argument("--delimiter", help=f"Delimiter between attribute names and values. Default is '{DEFAULT_DELIMITER}'")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    

    # Create mutually exclusive group for append and overwrite
    file_behavior = parser.add_mutually_exclusive_group()
    file_behavior.add_argument("--overwrite", action="store_true", 
                             help="This flag will overwrite existing data in folder.")
    file_behavior.add_argument("--append", action="store_true", 
                             help="If set, this flag appends new data to existing files. This may result in duplicates.")
    

    args = parser.parse_args()
    
    # Set up logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Get configuration values
    filename_seed = args.filenameSeed or DEFAULT_FILENAME_SEED
    delimiter = args.delimiter or DEFAULT_DELIMITER
    logon_count_threshold = args.logonCount or DEFAULT_LOGON_COUNT_THRESHOLD
    logon_date_threshold = args.logonDate or DEFAULT_LOGON_DATE_THRESHOLD
    
    # Validate input files
    if args.file and (args.users or args.groups or args.computers):
        logger.error("Please provide either a single file (-f) or separate files (-U, -G, -C), not both.")
        return 1
    
    if not args.file and not args.users and not args.groups and not args.computers:
        logger.error("No input files specified. Please provide at least one input file.")
        return 1
    
    # Initialize the AD collection
    ad_collection = ADCollection(args.directory)
    
    # Process input files
    if args.file:
        logger.info(f"Processing combined file: {args.file}")
        objects = parse_ad_file(args.file, filename_seed, delimiter, 
                              logon_count_threshold, logon_date_threshold)
        
        for obj in objects:
            ad_collection.add_object(obj)
    else:
        if args.users:
            logger.info(f"Processing users file: {args.users}")
            objects = parse_ad_file(args.users, filename_seed, delimiter,
                                  logon_count_threshold, logon_date_threshold, "usersFile")
            for obj in objects:
                ad_collection.add_object(obj)
        
        if args.groups:
            logger.info(f"Processing groups file: {args.groups}")
            objects = parse_ad_file(args.groups, filename_seed, delimiter,
                                  logon_count_threshold, logon_date_threshold, "groupsFile")
            for obj in objects:
                ad_collection.add_object(obj)
        
        if args.computers:
            logger.info(f"Processing computers file: {args.computers}")
            objects = parse_ad_file(args.computers, filename_seed, delimiter,
                                  logon_count_threshold, logon_date_threshold, "computersFile")
            for obj in objects:
                ad_collection.add_object(obj)
    
    # Write output
    logger.info(f"Writing output to {args.directory}")
    logger.info(f"File handling mode: {'Append' if args.append else 'Overwrite' if args.overwrite else 'Skip existing'}")
    ad_collection.write_all(args.overwrite, args.append)
    
    # Summary
    logger.info(f"Processed {len(ad_collection.users)} users, "
               f"{len(ad_collection.groups)} groups, "
               f"{len(ad_collection.computers)} computers")
    
    return 0


if __name__ == "__main__":
    exit(main())
