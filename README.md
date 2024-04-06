# python_autoban_ufw

**Working: enough for me**


Create 'honeypot' ports and automatically ban the IPs that try to connect to them.

Requires UFW. Tested on Ubuntu Server 22.04.

## Notes:
- Run the script as root (if you choose to use this for ports < 1024).
- Forward the ports in your router.
- This script automatically adds/deletes rules from UFW. Ensure the selected ports are not in use!

## Future Goals:
- Report IPs to online database
- Automatically port forward (UPnP?)
