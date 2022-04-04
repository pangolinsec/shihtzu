####################
##
## Block to define imports
##
####################
import argparse
from pathlib import Path
import re
import os
from datetime import *
import collections
import pickle

####################
##
## Block to set argument options
##
####################

parser = argparse.ArgumentParser(description="Shihtzu parses Active Directory attributes")
parser.add_argument("-f","--file",help="input file. Ideally .txt",required=False)
parser.add_argument("-D","--directory",help="Location of Obsidian Vault or subfolder for output",required=True)
parser.add_argument("--overwrite",action="store_true",help="This flag will overwrite data in folder. Defaults to not overwrite.")
parser.add_argument("--append",action="store_true",help="If set, this flag appends new data. This may result in duplicates.")
parser.add_argument("-G","--groups",help="input file containing groups. e.g. groups.txt",required=False)
parser.add_argument("-C","--computers",help="input file containing computers. e.g. computers.txt",required=False)
parser.add_argument("-U","--users",help="input file containing users. e.g. users.txt",required=False)
parser.add_argument("--logonCount",help="int value for how many logons you believe indicates an active user. Default is 100",required=False)
parser.add_argument("--logonDate",help="int value for how many days old a users last logon can be while still being active. Default is 30",required=False)
args = parser.parse_args()

####################
##
## Block to set variables, and include logic to update those variables
## if requested in command line args
##
####################

# What field you want your markdown files to be named off of?
# Currently this script does not check to ensure that the name does not
# Include "/\:" characters, which are forbidden by Obsidian in filenames
# If you choose a filename_seed that might have those characters in it
# You will have a bad time (or need to update the logic)
filenameSeed = "samaccountname"

# What is the delimiter between the value name and the value?
delimiter = ": "

# What is your threshold for an active user? The default threshold is 100
logonCountThreshold = 100

# Set threshhold date for stale logins. The default threshold is 30 days
logonDateThreshold = 30

# Set top level headers for the .md files
headers = {'rawdata': '# Raw Data:', 'tags': '# Tags:', 'time': '# Clean Timestamps:', 'members': '# Members:', 'parents': '# Parents:', 'uac': '# UserAccountControl Values:', 'userDefined': '# User Defined:'}



userPath = args.directory + "/USERS"
groupPath = args.directory + "/GROUPS"
computerPath = args.directory + "/COMPUTERS"

# Set new logonCountThreshold if user specifies such as an argument
if args.logonCount and type(int(args.logonCount)) == int:
	logonCountThreshold = int(args.logonCount)
elif args.logonCount and type(int(args.logonCount)) != int:
	print("logonCount value needs to be an integer!")

# Set new logonDateThreshold if user specifies such as an argument
if args.logonDate and type(int(args.logonDate)) == int:
	logonDateThreshold = int(args.logonDate)
elif args.logonDate and type(int(args.logonDate)) != int:
	print("logonDate value needs to be an integer!")


####################
##
## Block to define functions
##
####################

#Taken from impacket GetADUsers.py
def getUnixTime(t):
	# This is like Jan 1 1607 00:00.00 UTC
	t-= 116444736000000000
	# Windows uses like 100 nanosecond ticks, so get rid of that to handle unix more simply
	t /= 10000000
	# The following line causes recusion errors, so remember to do this when you want it.
	#t = str(datetime.fromtimestamp(self.getUnixTime(t)))
	return t

#Individually developed	
def useraccountcalc(val):
	# Convert the decimal value to hex, and then get rid of the "0x" at the front
	val = int(hex(int(val))[2:])
	# Create list of attributes and associated hex values for those attributes
	attrs = ["ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION", "ADS_UF_PASSWORD_EXPIRED", "ADS_UF_DONT_REQUIRE_PREAUTH", "ADS_UF_USE_DES_KEY_ONLY", "ADS_UF_NOT_DELEGATED", "ADS_UF_TRUSTED_FOR_DELEGATION", "ADS_UF_SMARTCARD_REQUIRED", "ADS_UF_MNS_LOGON_ACCOUNT", "ADS_UF_DONT_EXPIRE_PASSWD", "N/A", "N/A", "ADS_UF_SERVER_TRUST_ACCOUNT", "ADS_UF_WORKSTATION_TRUST_ACCOUNT", "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT", "ADS_UF_NORMAL_ACCOUNT", "ADS_UF_TEMP_DUPLICATE_ACCOUNT", "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED", "ADS_UF_PASSWD_CANT_CHANGE", "ADS_UF_PASSWD_NOTREQD", "ADS_UF_LOCKOUT", "ADS_UF_HOMEDIR_REQUIRED", "ADS_UF_ACCOUNTDISABLE", "ADS_UF_SCRIPT"]
	nums = [1000000, 800000, 400000, 200000, 100000, 80000, 40000, 20000, 10000, 8000, 4000, 2000, 1000, 800, 200, 100, 80, 40, 20, 10, 8, 2, 1]
	# Initialize "attributes" list which will store the attributes
	#	denoted by a given useraccountcontrol value
	attributes = []
	# Start loops to iterate through our useraccountcontrol value until
	# all applied attributes are identified
	while val > 0:
		# step through each element of the list at a given index
		for i in range(len(nums)):
			''' Uncomment elements of this block if you need to debug
			print(test[i])
			print(i)
			print(nums[i])
			'''
			# If our value is greater than or equal to a given hex value
			# then we know that it contains that value. So remove the
			# value and append the attribute at that index
			if val >= nums[i]:
				attributes.append(attrs[i])
				val -= nums[i]
			else:
				# Go back to the start of the loop and start again
				continue
	# Return the list of applied attributes
	return(attributes)

def linkGroups(var):
	var = "[[GROUPS/" + var + "]]"
	return var

def linkUsers(var):
	var = "[[USERS/" + var + "]]"
	return var

def linkComputers(var):
	var = "[[COMPUTERS/" + var + "]]"
	return var

def linkUACAttributes(var):
	var = "[[UserAccountControlValues#" + var + "]]"
	return var

def addToAppropriateDict(dictname):
	dictname.update({elementDict.get(filenameSeed)[0]: elementDict})

# Block of functions to allow clean checks for object type. You could
# also use samaccounttype values to help determine this, but this 
# requires less math and is, I believe, as accurate. If you do not want
# to pull back objectclass data (which has multiple values) and instead
# want only to pull back samaccounttype you might improve your stealth
# as fewer bits will have to flow back to you.
'''
fileKeys = files.keys()
fileKeys = list(fileKeys)
for fi in fileKeys:
	print("Reading from " + files[fi])
	with open(files[fi], 'r', encoding='utf-8-sig') as f:
'''
def isGroup():
	if elementDict['objectclass']:
		if "group" in elementDict['objectclass']:
			return True
		else:
			return False
	else:
		if fi == groupsFile:
			return True
		else:
			return False

def isComputerAsUser():
	if elementDict['objectclass']:

		if "computer" in elementDict['objectclass'] and not elementDict['operatingsystem']:
			return True
		else:
			return False
	else:
		if fi == computersFile:
			return True
		else:
			return False
			
def isComputerAsComputer():
	if elementDict['objectclass']:
		if "computer" in elementDict['objectclass'] and elementDict['operatingsystem']:
			return True
		else:
			return False
	else:
		if fi == computerFile:
			return True
		else:
			return False

# This block cleans up the member values. Fret not! No data is
# destroyed, since we still have rawdata as a dict entry. Also, I 
# thought this function would be more useful than it was...
def updateListEntryInDict(dictKey):
	existingKeyList = elementDict[dictKey]
	newlist = []
	for val in existingKeyList:
		# This cleans up from like cn=username,OU=blah
		val = val[3:].split(',')[0]
#		newlist.append(val.title())
		newlist.append(val)
	# Now set the new value for members in the dict
	elementDict.update({dictKey:newlist})
	# Debug line:
	#print(elementDict[dictKey])
''' If you want to get rid of this function above, you can use this block
to do this manually
			## Set Tags
			# This block cleans up the member values. Fret not! No data
			# is destroyed, since we still have rawdata as a dict entry
			if elementDict['member']:
				members = elementDict['member']
				newmembers = []
				#print(members)
				for member in members:
					# This cleans up from like cn=username,OU=blah
					member = member[3:].split(',')[0]
					newmembers.append(member)
				# Now set the new value for members in the dict
				elementDict.update({'member':newmembers})
				# Debug line:
				#print(elementDict['member'])
'''

# Function beautifies ugly windows time vals and also tags stale logons
def updateTimeEntryInDict(listOfKeys):
	for key in listOfKeys:
		if elementDict[key]:
			#print(elementDict[key])
			Win64BitTime = int(elementDict[key][0])
			#print(Win64BitTime)
			if Win64BitTime != 0:
					cleantime = datetime.fromtimestamp(getUnixTime(Win64BitTime))
					convertedTime = str(cleantime)
					#print(convertedTime)
					elementDict.update({key:convertedTime})
					if key == "lastlogon":
						if cleantime < datetime.utcnow() - timedelta(days=logonDateThreshold):
							elementDict['tags'].append("#BadAccount due to #StaleLogons at this Domain Controller")
					elif key == "lastlogontimestamp":
						if cleantime < datetime.utcnow() - timedelta(days=logonDateThreshold):
							elementDict['tags'].append("#BadAccount due to #StaleLogons replicated across the Domain. See info on 'lastlogontimestamp' attribute for more information.")
					#print(elementDict[key])

# Func to be run on group objects with admincount=1. This function will
# tag all 'heirs' of any admin group with "#GroupIsAdmin" if a group or
# "IsAdmin" if a user.
# Of note: this function needs to be called after groups are fully
# populated.
def tagAsAdmin(samaccountname, origin=True):
	if origin:
		global originname
		originname = samaccountname
	if groupDict[samaccountname]:
		for member in groupDict[samaccountname].get('member'):
#			mem = member.lower()
			mem = member
			if groupDict[mem]:
				#mem = member.lower()
				#print(mem)
#				groupDict[mem]['tags'].append("#GroupIsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in " + originname.title())
				groupDict[mem]['tags'].append("#GroupIsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in " + originname)
				#print(groupDict[mem]['tags'])
				#groupDict[member.lo
				tagAsAdmin(mem, False)
			if userDict[mem]:
#				userDict[mem]['tags'].append("#IsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in " + originname.title())
				userDict[mem]['tags'].append("#IsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in " + originname)
				#print("#IsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in " + originname.title())
				#print(userDict[mem]['tags'])
			if computerDict[mem]:
#				computerDict[mem]['tags'].append("#ComputerIsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in " + originname.title())
				computerDict[mem]['tags'].append("#ComputerIsAdmin based on group parentage tied to admincount=1, ultimately derived from membership in " + originname)
#		print(member)



def writeData(dictOfUserGroup_or_Computer):
	keys = dictOfUserGroup_or_Computer.keys()
	keys = list(keys)
	if dictOfUserGroup_or_Computer == userDict:
		targetPath = userPath
	elif dictOfUserGroup_or_Computer == groupDict:
		targetPath = groupPath
	elif dictOfUserGroup_or_Computer == computerDict:
		targetPath = computerPath
	else:
		print("Please specifiy an appropriate dictionary. You should only ever see this message if you have tweaked the code and broken something therein.")
	for key in keys:
		if len(dictOfUserGroup_or_Computer[key]) > 0:
#		if key == "administrators":
			#
			targetFile = targetPath + "/" + key + ".md"
			targetFile = open(targetFile, "w")
			#print(userFile)
#			print(''.join(userDict[key][rawdata]))
			#print(userDict[key]['rawdata'])
			
			## Create the raw data and write it
			raw = dictOfUserGroup_or_Computer[key]['rawdata'][0]
			raw.insert(0,"\n```plaintext raw")
			raw.insert(0, headers['rawdata'])
			raw.append("```")
			raw = '\n'.join(raw)
			#print(raw)
			targetFile.write(raw)
			
			## Write the members.
			if dictOfUserGroup_or_Computer[key]['member']:
				members = dictOfUserGroup_or_Computer[key]['member']
				#print(members)
				mems = []
				for mem in members:
					#print(mem)
					#if mem is a group:
					linkedMem = ''
					if groupDict[mem]:
						#print(linkGroups(mem))
						mems.append(linkGroups(mem))
						#print(linkGroups(mem))
					elif computerDict[mem]:
						#print(linkComputers(mem))
						mems.append(linkComputers(mem))
					elif userDict[mem]:
						#print(linkUsers(mem))
						mems.append(linkUsers(mem))
					# This Else catches exceptions where a user drops
					# extra data in the members field in our append
					# function
					else:
						mems.append(mem)
				mems.insert(0, "\n" + headers['members'])
				mems = '\n'.join(mems)
				targetFile.write(mems)
			else:
				targetFile.write("\n" + headers['members'])
				#print(mems)
			
			## Write the parents. Users won't have members, so we won't
			# bother with that
			if dictOfUserGroup_or_Computer[key]['memberof']:
				parents = dictOfUserGroup_or_Computer[key]['memberof']
				pars = []
				for parent in parents:
					#print(mem)
					#if mem is a group:
					linkedParent = ''
					if groupDict[parent]:
						#print(linkGroups(parent))
						pars.append(linkGroups(parent))
						#print(linkGroups(parent))
					elif computerDict[parent]:
						#print(linkComputers(parent))
						pars.append(linkComputers(parent))
					elif userDict[parent]:
						#print(linkUsers(parent))
						pars.append(linkUsers(parent))
					# This Else catches exceptions where a user drops
					# extra data in the parents field in our append
					# function
					else:
						pars.append(parent)
				#print(pars)
				pars.insert(0, "\n" + headers['parents'])
				pars = '\n'.join(pars)
				#print(pars)
				targetFile.write(pars)
				#print(mems)
			else:
				targetFile.write("\n" + headers['parents'])
				
				
			## Write the tags
			if dictOfUserGroup_or_Computer[key]['tags']:
				tags = dictOfUserGroup_or_Computer[key]['tags']
				tags.insert(0, "\n" + headers['tags'])
				targetFile.write('\n'.join(tags))
			else:
				targetFile.write("\n" + headers['tags'])
				
			## Write the useraccountcontrol values
			if dictOfUserGroup_or_Computer[key]['uacval']:
				'''
				uac = dictOfUserGroup_or_Computer[key]['uacval'][0]
				print(uac)
				targetFile.write("\n" + headers['uac'])
				targetFile.write("\n[[UserAccountControlValues#")
				targetFile.write(']]\n[[UserAccountControlValues#'.join(uac))
				targetFile.write("]]")
				'''
				
				
				#print(dictOfUserGroup_or_Computer[key]['uacval'])
				uac = dictOfUserGroup_or_Computer[key]['uacval'][0]
				#print(uac)
				newU = []
				#print(uac)
				targetFile.write("\n" + headers['uac'] + "\n")
				for u in uac:
					if u.upper().startswith("ADS"):
						newU.append("[[UserAccountControlValues#" + u + "]]")
					else:
					#elif u != '\n':
						#print(u)
						newU.append(u)
						#print(u)
				targetFile.write('\n'.join(newU))
				#print(newU)
				#targetFile.write("\n[[UserAccountControlValues#")
				#targetFile.write(']]\n[[UserAccountControlValues#'.join(uac))
				#targetFile.write('\n'.join(newU))
				#targetFile.write("]]")
				#uac.insert(0, "\n# UserAccountControl values:")
				#userFile.write("[[UserAccountControlValues#")
				#userFile.write('\n[[UserAccountControlValues#'.join(uac))
				#userFile.write("]]")
				#userFile.write('\n'.join(uac))
				#print(uac)
			# If the list uacval doesn't exist, then just write the
			# header for useraccountcontrol values and a newline
			else:
				targetFile.write("\n" + headers['uac'] + "\n")
				
			## Write the clean timestamps
			#if userDict[key][convertedTime]
			cleanTimeStamps = []
			for i in ['pwdlastset', 'badpasswordtime', 'lastlogon', 'lastlogontimestamp']:
				if type(dictOfUserGroup_or_Computer[key][i]) != list:
					cleanTimeStamps.append(i + delimiter	+ dictOfUserGroup_or_Computer[key][i])
			cleanTimeStamps.insert(0, "\n" + headers['time'])
			targetFile.write('\n'.join(cleanTimeStamps))
				#else:
				#	targetFile.write("\n" + headers['time'])
			if dictOfUserGroup_or_Computer[key]['cleantime']:
				targetFile.write("\n")
				targetFile.write('\n'.join(dictOfUserGroup_or_Computer[key]['cleantime']))

			# Write the User Defined section header
			targetFile.write("\n" + headers['userDefined'])
			if dictOfUserGroup_or_Computer[key]['userDefined']:
				targetFile.write('\n'.join(dictOfUserGroup_or_Computer[key]['userDefined']))
			targetFile.close()



####################
##
## Start body of code to read from data flowing in
##
####################



# Long term storage for the whole dataset
#groupDict = {}
groupDict = collections.defaultdict(list)
#userDict = {}
userDict = collections.defaultdict(list)
#computerDict = {}
computerDict = collections.defaultdict(list)

# Ephemeral storage per element
elementDict = collections.defaultdict(list)




# There are surely better ways to do this, but this initializes a list 
# that we will loop through to get the input files.
files = {}
if args.file and not args.users and not args.groups and not args.computers:
	files["fileFile"] = args.file
elif args.file and args.users or args.file and args.groups or args.file and args.computers:
	print("Oops, please select only a concatenated file, or separate files")
	print("Exiting now.")
	exit()

if args.users or args.groups or args.computers:
	files = {}
if args.users:
	files["usersFile"] = args.users
	#files.update("Users": args.users)
#	files.append(args.users)
if args.groups:
	files["groupsFile"] = args.groups
	#files.append(args.groups)
if args.computers:
	files["computersFile"] = args.computers
	#files.append(args.computers)
#print(elementDict)

fileKeys = files.keys()
fileKeys = list(fileKeys)
for fi in fileKeys:
	print("Reading from " + files[fi])
	with open(files[fi], 'r', encoding='utf-8-sig') as f:
		#subpath = "/USERS"
		# initialize tags
		tags = []
		# initialize timestamp values:
		time = []
		# initialize rawdata. This list will hold raw data
		rawdata = []
		for line in f.readlines():
			rawdata.append(line.strip())
			
			# Split each line along the delimiter into a list, with attr
			# name at index 0 and attr value at index 1. And make lowercase
			# and strip whitespace characters from the ends
#			line = line.lower().strip().split(delimiter)
			line = line.strip().split(delimiter)
			#print(line)
			#print(len(line))
			if len(line) == 2:
				elementDict[line[0]].append(line[1])
				#print(elementDict)
			
			# Throw an error if len(line) is not 2 or 1
			elif len(line) != 2 and len(line) != 1:
				print("There was an error. len(line) returned " + str(len(line)) + " but that value should only be 2 or 1!\nMaybe check your delimiter value and confirm that your elements are separated by an empty line?")
				exit()
			
			# This else condition should always and only occur when
			# len(line) == 1, which is the expected outcome for an empty
			# line which should be separating elements. At this point, we 
			# are going to conduct some operations on values of our dict
			# and we are going to set some new keys like tags and append 
			# values to them.
			# This would be slightly faster to do under the case where
			# len(line) == 2, but since there is a pre-determined number
			# of attributes, this isn't killing us on complexity. It is 
			# much more important to conserve our for loops, and be very 
			# stingy with anything dealing with members or iterating through
			# users! Since there can be scads of those.
			else:
				#print(''.join(rawdata))
				elementDict['rawdata'].append(rawdata)
				
				# If there are members, update the members as a clean list
				# in the dictionary
				if elementDict['member']:
					updateListEntryInDict('member')
					#print(elementDict['member'])
				
				# If there are parents, update the parents as a clean list
				# in the dictionary
				if elementDict['memberof']:
					updateListEntryInDict('memberof')
				
				if elementDict['logoncount']:
					logoncount = int(elementDict['logoncount'][0])
					#print(logoncount)
					if logoncount < logonCountThreshold:
						elementDict['tags'].append('#BadAccount due to #LowLogonCount at this Domain Controller')
				
				# Call function to run through a bunch of ugly windows time
				# values and conver them to pretty timestamps.
				# This function also tags stale logons
				updateTimeEntryInDict(['pwdlastset', 'badpasswordtime', 'lastlogon', 'lastlogontimestamp'])
				
				# This chunk will look for useraccountcontrol values, call
				# a function to calculate the relevant attributes, and 
				# apply them as tags.
				if elementDict['useraccountcontrol']:
					#print(elementDict['useraccountcontrol'][0])
					uacval = elementDict['useraccountcontrol'][0]
					uacval = useraccountcalc(uacval)
					# Create a new dictionary key of 'uacval' and add
					# to it the value of uacval (a list)
					elementDict['uacval'].append(uacval)
					# Need to add a uacval entry into the dictionary.
					#print(uacval)
					if "ADS_UF_SMARTCARD_REQUIRED" in uacval:
						elementDict['tags'].append("#SmartcardRequired")
					if "ADS_UF_LOCKOUT" in uacval or "ADS_UF_ACCOUNTDISABLE" in uacval:
						elementDict['tags'].append('#BadAccount due to #DisabledOrLockedAccount at this Domain Controller')
					if "ADS_UF_PASSWORD_EXPIRED" in uacval:
						elementDict['tags'].append('#BadAccount because #PasswordExpired at this Domain Controller')
					if "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION" in uacval or "ADS_UF_TRUSTED_FOR_DELEGATION" in uacval:
						elementDict['tags'].append('#DelegationOpportunity')
					if "ADS_UF_NORMAL_ACCOUNT" in uacval:
						elementDict['tags'].append('#NormalAccount')
					if "ADS_UF_SERVER_TRUST_ACCOUNT" in uacval:
						elementDict['tags'].append("#ServerTrustAccount")
				
				# I haven't ever seen this, actually, so it is not field
				# tested. Just including it here because it would be so
				# juicy to find
				if elementDict['userpassword']:
					elementDict['tags'].append("#Creds because of #UserPasswordAttribute. This is a #HighImportance finding!")

				# Check if something is a group
				if isGroup():
					#print("group!")
					addToAppropriateDict(groupDict)
				
				# Check if something is a computer, and that it has all of
				# the attributes of a computer, not just a user
				# This gets the condition if this is a computer from Users
				elif isComputerAsUser():
					#print("Computer as user!")
					addToAppropriateDict(computerDict)
					
				# In this case, I want to put it into my computerDict,
				# but overwrite it if I find it as a computer
				elif isComputerAsComputer():
					addToAppropriateDict(computerDict)
					''' #If you want to add a conditional in the event that you have already
					# added that computer account with user attributes to computerDict,
					# then uncomment this block and use the following two lines
					if elementDict['samaccountname'][0] in computerDict:
						print("found")
					'''
				# if none of the conditions (isGroup and isComputer*) are
				# met, then it is a user
				else:
					#print("user!")
					addToAppropriateDict(userDict)
				#if elementDict['member']:
				#	for member in elementDict["member"]:
				#		#print(member)
				


					
					
			#if len(line) != 0:
			#	data.append(line)
			# If the line does not have content, then we know it is a divider
				
				# Set tags and members etc
				# DO all enrichment here
				# Write to file
				# Add the dictionary to userDict with a key of the value of
				# the filenameseed (defined as a var above) of elementDict, and the value of 
				# elementDict itself
				elementDict = collections.defaultdict(list)
				rawdata = []
		
		# This loops through all of the group entries and if a group has
		# admincount, runs our tagAsAdmin function
		# We need to create a new variable "keys" and loop through that,
		# Since we can't loop through a dictionary while it is changing size
		keys = groupDict.keys()
		keys = list(keys)
		for key in keys:
			# Check that admincount exists, and that the value is non-zero
			if groupDict[key]['admincount'] and groupDict[key]['admincount'][0] != '0':
				tagAsAdmin(groupDict[key]['samaccountname'][0])

#pickle.dump(userDict, open("filename.p", "wb"))
#userDict2 = pickle.load(open("filename.p","rb"))
#print(userDict2)



########
##
## We are going to start writing stuff here. Strap in! The code gets
## uglier...
##
########

# Create directories at path if they don't already exist:
if len(userDict) > 0:
#	userPath = args.directory + "/USERS"
	if not os.path.exists(userPath):
		os.makedirs(userPath)
		print("[+] Creating new directory at " + userPath)
	else:
		print("[+] " + userPath + " already exists. Using it now.")
if len(groupDict) > 0:
#	groupPath = args.directory + "/GROUPS"
	if not os.path.exists(groupPath):
		os.makedirs(groupPath)
		print("[+] Creating new directory at " + groupPath)
	else:
		print("[+] " + groupPath + " already exists. Using it now.")
if len(computerDict) > 0:
#	computerPath = args.directory + "/COMPUTERS"
	if not os.path.exists(computerPath):
		os.makedirs(computerPath)
		print("[+] Creating new directory at " + computerPath)
	else:
		print("[+] " + computerPath + " already exists. Using it now.")

#print(groupDict['Administrators']['member'])
#####
##
## Write the data here if overwriting
##
#####
if args.overwrite:
	writeData(groupDict)
	writeData(userDict)
	writeData(computerDict)

#####
##
## More complex, append data here if appending
##
#####

elif args.append:
	headerVals = headers.values()
	headerVals = list(headerVals)
	keys = groupDict.keys()
	keys = list(keys)
	#for key in groupDict.keys():
	for key in keys:
		indices = []
		if len(groupDict[key]) > 0:
# Debug line
#		if key == "Administrators":
			#print(key)
			appendFile = groupPath + "/" + key + ".md"
			with open(appendFile, 'r') as newfile:
				lines = newfile.readlines()
				totalLen = len(lines)
				#print(lines)
				for l in lines:
					#if l.strip() in headerVals:
						#indices.append(lines.index(l))
					# This line checks if the the line is # Raw Data
					if l.strip() in headerVals and "raw" in l.strip().lower():
						# Start our index counter at 3, because that is
						# how many values we need to offset to get the 
						# first actual rawdata value and avoid "```" and
						# "\n" and other garbage
						count = 3
						v = ''
						oldRawData = []
						# This loop runs until we hit the closing of the
						# rawdata block. It iterates through each line
						# and adds it into newRawData
						while v.strip() != "```":
							# This makes v equal to the new line 
							v = lines[lines.index(l)+count]
							# And this appends it to our list
							oldRawData.append(v.strip())
							# Iterates counter for next list item
							count += 1
							#print('\n'.join(newRawData[:-1]))
							#print(newRawData[:-1])
						# Looks through our rawdata list
						for data in oldRawData[:-1]:
							data = data.strip()
							# If there are any elements in oldRawData
							# that don't exist in our new data, then we
							# want to append those to our new data.
							if data not in groupDict[key]['rawdata'][0]:
								groupDict[key]['rawdata'][0].insert(-1,data)
#								print(groupDict)
								#newRawData.insert()data + "\n" + oldRawData[count-1]
#						for data in groupDict[key]['rawdata'][0]:
#							if data not in oldRawData[:-1]:
								

					elif l.strip() in headerVals and "# Members" in l.strip():
						#print(l)
						
						
						# Start our index counter at 1, because that is
						# how many values we need to offset to avoid  
						# hitting ourselves
						count = 1
						v = ''
						oldMembers = []
						# This loop runs until we hit the next header
						# block. It iterates through each line and adds
						# it into oldMembers
						while not v.strip().startswith("# "):
							#print(v.strip())
							# This makes v equal to the new line 
							#print(count)
							v = lines[lines.index(l)+count]
							# And this appends it to our list
							oldMembers.append(v.strip())
							# Iterates counter for next list item
							count += 1
						# Looks through our old members list and 
						# compares with new
						#print('\n'.join(groupDict[key]['member']))
						#print(oldMembers)
						for data in oldMembers[:-1]:
							data = data.strip()
							#print(data)
							if data.startswith("[[") and "/" in data:
								data = data.split("/")[-1][:-2]
							elif data.startswith("[["):
								data = data[2:-2]								
							#print(data)
							# If there are any elements in oldMembers
							# that don't exist in our new data, then we
							# want to append those to our new data.
							if data not in groupDict[key]['member']:
								#print(data)
								groupDict[key]['member'].append(data)
								#print(groupDict[key]['member'])
						#print('\n'.join(groupDict[key]['member']))
								#groupDict[key]['member'].insert(-1,data)
								#newRawData.insert()data + "\n" + oldRawData[count-1]


					elif l.strip() in headerVals and "# Parents" in l.strip():
						# Start our index counter at 1, because that is
						# how many values we need to offset to avoid  
						# hitting ourselves
						#print(l)
						count = 1
						v = ''
						oldParents = []
						# This loop runs until we hit the next header
						# block. It iterates through each line and adds
						# it into oldMembers
						while not v.strip().startswith("# "):
							#print(v.strip())
							# This makes v equal to the new line 
							v = lines[lines.index(l)+count]
							#print(v)
							# And this appends it to our list
							oldParents.append(v.strip())
							# Iterates counter for next list item
							count += 1
						#print(oldParents)
						# Looks through our old members list and 
						# compares with new
						#print(oldParents)
						for data in oldParents[:-1]:
							data = data.strip()
							#print(data)
							if data.startswith("[[") and "/" in data:
								data = data.split("/")[-1][:-2]
							elif data.startswith("[["):
								data = data[2:-2]
							#print(data)
							# If there are any elements in oldMembers
							# that don't exist in our new data, then we
							# want to append those to our new data.
							if data not in groupDict[key]['memberof']:
								#print(data)
								groupDict[key]['memberof'].append(data)
								#newRawData.insert()data + "\n" + oldRawData[count-1]
						#print('\n'.join(groupDict[key]['memberof']))
						
					elif l.strip() in headerVals and "# Tags" in l.strip():
						# Start our index counter at 1, because that is
						# how many values we need to offset to avoid  
						# hitting ourselves
						count = 1
						v = ''
						oldTags = []
						# This loop runs until we hit the next header
						# block. It iterates through each line and adds
						# it into oldMembers
						while not v.strip().startswith("# "):
							#print(v.strip())
							# This makes v equal to the new line 
							v = lines[lines.index(l)+count]
							# And this appends it to our list
							oldTags.append(v.strip())
							# Iterates counter for next list item
							count += 1
						#print(oldParents)
						# Looks through our old members list and 
						# compares with new
						for data in oldTags[:-1]:
							data = data.strip()
							#print(data)
							# If there are any elements in oldMembers
							# that don't exist in our new data, then we
							# want to append those to our new data.
							if data not in groupDict[key]['tags']:
								groupDict[key]['tags'].append(data)
								#newRawData.insert()data + "\n" + oldRawData[count-1]
						#print('\n'.join(groupDict[key]['memberof']))
						
						
					elif l.strip() in headerVals and "# UserAccountControl Values" in l.strip():
						# Start our index counter at 3, because that is
						# how many values we need to offset to get the 
						# first actual rawdata value and avoid "```" and
						# "\n" and other garbage
						count = 1
						v = ''
						oldUAC = []
						newUAC = []
						# This exists because of some bad code that I
						# need to fix...
						secondListWrapper = []
						# This loop runs until we hit the closing of the
						# rawdata block. It iterates through each line
						# and adds it into newRawData
						while not v.strip().startswith("# "):
							# This makes v equal to the new line 
							v = lines[lines.index(l)+count]
							#print("v is: " + v.strip())
							# And this appends it to our list
							oldUAC.append(v.strip())
							# Iterates counter for next list item
							count += 1
							#print('\n'.join(newRawData[:-1]))
							#print(newRawData[:-1])
						# Looks through our rawdata list
						#print(
						if groupDict[key]['uacval']:
							#print("key is " + key)
							#print("exists, and uacval is: ")
							#print(uacval)
							for u in uacval:
								groupDict[key]['uacval'][0].append(u)
							#print("exists")
						else:
							#print("orig is:")
							#print(groupDict[key]['uacval'])
							#for u in oldUAC:
							groupDict[key]['uacval'].append(oldUAC[:-1])
							#print("new is:")
							#print(groupDict[key]['uacval'])
						#oldUAC = oldUAC[:-1]

					elif l.strip() in headerVals and "# Clean T" in l.strip():
						count = 1
						v = ''
						oldTime = ["\n"]
						currentLine = lines.index(l)
						#print(currentLine)
						#print(totalLen)
						while not v.strip().startswith("# "):
							#print(v.strip())
							# This makes v equal to the new line 
							v = lines[lines.index(l)+count]
							# And this appends it to our list
							oldTags.append(v.strip())
							# Iterates counter for next list item
							count += 1

						for data in oldTags[:-1]:
							data = data.strip()

							groupDict[key]['cleantime'].append(data)

					elif l.strip() in headerVals and "# User De" in l.strip():
						count = 1
						v = ''
						userDef = ["\n"]
						currentLine = lines.index(l)
						#print(currentLine)
						#print(totalLen)
						while count <= totalLen-currentLine-1:
							v = lines[lines.index(l)+count]
							userDef.append(v.strip())
							count += 1

						for data in userDef:
							data = data.strip()
							#print("data is: "+data)
							groupDict[key]['userDefined'].append(data)
	writeData(groupDict)
	writeData(userDict)
	writeData(computerDict)
