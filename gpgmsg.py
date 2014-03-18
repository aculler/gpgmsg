# gpgmsg.py
#
# I am writing this script to allow myself to more easily respond to messages that are sent to me
# via GPG encrypted files.

import gnupg
import os
import sys
import getpass
import re

# Global variables
_gpg = None
_gnupg_home_dir = ""

# Function to set up the script for the first time or load the configs.
# 
# Parameters: 
#		None
#
# Return value:
#		None
def setup_config():
	conf_file = os.path.expanduser("~/.gpgmsg/gpgmsg.conf")
	gnupg_conf_dir = os.path.expanduser("~/.gpgmsg/gnupg/")

	if not os.path.exists(conf_file):
		# Initial config required.
		os.makedirs(os.path.dirname(conf_file))
		
		conf_string = """GNUPG_HOME_DIR,~/.gpgmsg/gnupg/
"""

		f = open(conf_file, "w")
		f.write(conf_string)
	conf = open(conf_file, "r")
	# Read in the configuration.

	for line in conf:
		line = line.strip().split(',')
		if not len(line) == 2:
			next
		else:
			# Read in the GNUPG home directory. Used to load keys etc
			if line[0] == "GNUPG_HOME_DIR":
				global _gnupg_home_dir 
				_gnupg_home_dir = line[1]
				# If the path is relative to the home dir, expand it.
				if re.match("^~", _gnupg_home_dir):
					print "[+] Expanding _gnupg_home_dir"
					_gnupg_home_dir = os.path.expanduser(_gnupg_home_dir)

				# Create the directory if it doesn't exist.
				if not os.path.exists(_gnupg_home_dir):
					print "[+] Directory does not exist. Creating"
					os.mkdir(_gnupg_home_dir)

# Function to set up the global gnupg object.
#
# Parameters:
#		None
# Return value:
#		None
def gpg_conf():
	global _gpg
	if not _gnupg_home_dir:
		print "[!] ERROR: gpg_conf: no _gnupg_home_dir specified"
		sys.exit(-1)

	_gpg = gnupg.GPG(gnupghome=_gnupg_home_dir)

# Function to decrypt a message.
#
# Parameters:
#		crypt_text	- Text that needs to be decrypted
#		passphrase	- GPG passphrase that is needed to decrypt the text
#
# Return value:
#		Decrypted message or an error code.
def gpg_decrypt( crypt_text, pphrase ):
	# Kill the script if data is omitted
	if crypt_text == "" or pphrase == "":
		print "[!] ERROR: gpg_decrypt: missing crypt_text or passphrase"
		sys.exit(-1)

	# Time to decrypt!
	dec_obj = _gpg.decrypt(crypt_text,passphrase=pphrase)

	if not dec_obj.ok:
		print "[!] ERROR: gpg_decrypt: Failed to decrypt message"
		print dec_obj.stderr
		sys.exit(-1)

	return dec_obj.data

# Function to encrypt a message
#
# Parameters:
#		message_text	- Text that needs to be encrypted
#		email		- Email associated with the public key to encrypt with
# Return value:
#		Encrypted message or an error code.
def gpg_encrypt( message_text, email ):
	# Kill the script if data is omitted
	if message_text == "" or email == "":
		print "[!] ERROR: gpg_encrypt: missing message_text or email"
		sys.exit(-1)

	# Time to encrypt! Yea baby!
	enc_obj = _gpg.encrypt(message_text, email, always_trust=True)

	if not enc_obj.ok:
		print "[!] ERROR: gpg_encrypt: Failed to encrypt message"
		print enc_obj.stderr
		sys.exit(-1)

	return str(enc_obj)

# Function to import a GPG key file
#
# Parameters:
#		file_contents	- Data to import
#
# Return value:
#		Boolean regarding success
def gpg_import_key( file_contents ):
	# Kill the script if data is omitted
	if file_contents == "":
		print "[!] ERROR: gpg_import_key: missing file_name"
		sys.exit(-1)

	print "file_contents length: " + str(len(file_contents))
	# Time to get crackin' on the key import! Heeyaw!
	import_result = _gpg.import_keys(file_contents)

	if import_result.count == 0:
		print "[!] ERROR: gpg_import_key: No keys imported"
		print import_result.stderr
		sys.exit(-1)
	else:
		return True

# Function to return an array of email adresses for all of the public keys we have in the store
#
# Parameters:
#		None
# Return value:
#		Array of email addresses associated with public keys in the store
def gpg_pub_key_emails():
	return _gpg.list_keys()

# Function to normalize filenames to abs paths and check that the file exists
#
# Parameters:
#		filename 	- File name to verify/expand the absolute path and verify it exists
#		must_exist	- Switch to determine if the file must exist. Default: True
# Return value:
#		Absolute path to filename
def normalize_filename( filename, must_exist=True ):
	if filename == "":
		print "[!] ERROR: normalize_filename: Invalid filename"
		sys.exit(-1)
	
	if not type(must_exist) is bool:
		print "[!] ERROR: normalize_filename: Parameter 'must_exist' must be boolean"
		sys.exit(-1)

	if re.match("^~/", filename):
		print "[+] Expanding ~ to absolute path"
		filename = os.path.expanduser(filename)
	elif not os.path.isabs(filename):
		print "[+] Generating absolute path"
		filename = os.path.join(os.getcwd(), filename)

	# Time to check if we need to ensure the file exists before returning the path and return
	# the path as appropriate
	if must_exist == False:
		return filename
	else:
		if not os.path.exists(filename):
			return None
		else:
			return filename

#
# Main Program Loop
#
print "[+] Loading config"
setup_config()
print "[+] Configuring gnupg"
gpg_conf()
if _gpg is None:
	print "[!] ERROR: Main loop: _gpg is None"
	sys.exit(-1)
# Begin prompt loop
while 1:
	print """
########## Menu ##########
[1] Import Key
[2] Decrypt Message
[3] Exit"""
	options = raw_input("[>] ")

	if options == "1":
		print "[+] Importing key"
		key_file = raw_input("[>] Key file: ")
		key_file = normalize_filename(key_file)
		if key_file is None:
			print "[!] ERROR: File does not exist"
			break
		
		print "[+] Found: " + key_file
		key_data = open(key_file, "r").read()

		if len(key_data) == 0:
			print "[!] ERROR: File " + msg_file + " exists but is empty"
			break

		gpg_import_key(key_data)
		print "[+] Import successful"

	elif options == "2":
		print "[+] Decrypting message"
		msg_file = raw_input("[>] Message Filename: ")

		if msg_file == "":
			print "[!] ERROR: Invalid input"
			break

		msg_file = normalize_filename(msg_file)
		if msg_file == None:
			print "[!] ERROR: File does not exist"
			break

		print "[+] Found: " + msg_file

		# If the script has made it to here, the file name should be usable to open the file

		# Request the passphrase to decrypt with
		dec_pass = getpass.getpass("[>] GPG Decryption Passphrase: ")
		enc_file_text = open(msg_file, 'r').read()
		if len(enc_file_text) == 0:
			print "[!] ERROR: File " + msg_file + " exists but is empty"
			break

		dec_msg = gpg_decrypt(enc_file_text, dec_pass)
		print "dec_msg type: " + str(type(dec_msg))
		if re.match("^[!] ERROR:", dec_msg):
			print dec_msg
			break
		else:
			dec_msg = dec_msg.strip()
			print dec_msg

		# Ask if the user would like to respond
		respond = raw_input("[>] Respond? (Y/n): ").lower()

		if respond == "n":
			print "[+] Not responding"
			break
		elif respond == "y" or respond == "":
			print "[+] Responding"
		else:
			print "[!] ERROR: Invalid input"
			break

		# Loop through the decrypted message and add > to the front of each line.
		tmp_msg = ""

		for line in dec_msg.split('\n'):
			tmp_msg += "> " + line + "\n"

		dec_msg = tmp_msg

		# If we got here it's because we are responding
		pub_key_emails = gpg_pub_key_emails()
		
		if not pub_key_emails:
			print "[!] ERROR: No public keys imported. Please import public keys to respond"
			break

		# Take user input until the enter a line with only a period on it
		input_data = []

		while True:
			new_data = raw_input("> ");
			if new_data == ".":
				break
			else:
				input_data.append(new_data)

		output = ""
		for line in input_data:
			output += line + "\n"

		reply_body = output + "\n\n" + dec_msg

		# If we get here we have at least one public key imported
		response_email = raw_input("[>] Encrypt for? (email): ")

		# Specify the file to write out to.
		reply_file = raw_input("[>] File to store reply? (" + msg_file + "): ")

		if reply_file == "":
			reply_file = msg_file
		else:
			reply_file = normalize_filename(reply_file, must_exist=False)

		print "[+] Encrypting reply in: " + msg_file
		enc_reply = gpg_encrypt(reply_body,response_email)

		if re.match("^[!] ERROR:", enc_reply):
                        print enc_reply
                        break

		print "[+] Writing reply to file"
		output = open(reply_file, "w").write(enc_reply)
		print "[+] Reply successfully encrypted and written to " + reply_file

	elif options == "3":
		print "[+] Quitting..."
		sys.exit(0)
	else:
		print "[?] Invalid option"
