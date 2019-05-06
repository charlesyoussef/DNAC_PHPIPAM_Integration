# DNAC_PHPIPAM_Integration

*This script automatically syncs the DNAC host information inside the specified IPAM subnet*

It does so by:
1. Importing the host Database from DNAC and adding it to Phpipam.
2. Deleting any any stale hosts (addresses in IPAM terms) from the corresponding Phpipam subnet.

The RBAC control on the subnet management is natively built inside Phpipam,
which can be easily consumed from the Web interface of Phpipam.

---
 

## Usage

Firstly update the variables for the DNAC and PHPIPAM in the env_lab.py variable file.

Run the python script on-demand to sync the DNAC host Database and PHPIPAM Subnet.

## Installation

- Python package prerequisite:
pip install -r requirements.txt

- For development & testing, the PHPIPAM docker image below was used:
https://hub.docker.com/r/pierrecdn/phpipam/


## Authors & Maintainers

- Charles Youssef <cyoussef@cisco.com>

## Credits

PHPIPAM docker image used:
https://hub.docker.com/r/pierrecdn/phpipam/


## License

This project is licensed to you under the terms of the [Cisco Sample Code License](./LICENSE).
