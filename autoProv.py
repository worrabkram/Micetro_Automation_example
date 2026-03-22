#!/usr/bin/python3
#
# autoProv.py: Mark Barrow / Bluecat Networks / Mar 2026
# Example Auto Provisioning Script - Event Hook script
# This script when run as a Event Hook | Scheduled Event will search Micetro for Networks tagged with
# auto-provision data within custom properties and use this to automatically create the target networks
# on routers
# This script uses a VyOS based router (https://vyos.io/) as an example
#
# This should be copied to the Micetro central scripts directory and then added to Change events under Admin || Configuration || Event Hooks
# This is an example implementation. No warranty or support implied.
#

__version__ = '0.0.2'

import argparse

import requests
from pyvyos import VyDevice
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import json
import ipaddress
import logging.handlers
import os, random, string
from cryptography.fernet import Fernet

# text to pre-pend encrypted auth in autoProvGroups
ENCRYPTION_PREFIX = 'EEEEEE'

sess = requests.Session()
headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
}


def createMissingCustomFields():
    if not hasCustomProperty("Range", "auto-provision"):
        logger.info("Creating custom property definition 'auto-provision' for Networks")
        param = '{"objType": "Range", "propertyDefinition": {"name": "auto-provision", "type": "String", "readOnly": false, "listItems": ["add","delete","none","provisioned"],"defaultValue":"none"},"saveComment":"added by autoProv.py"}'
        sess.post(configuration['url'] + 'AddPropertyDefinition', auth=(username, password), headers=headers,
                  data=param, verify=configuration['validateCert'])
        logger.info("Creating custom property definition 'provision-grp' for Networks")
        param = '{"objType": "Range", "propertyDefinition": {"name": "provision-grp", "type": "String", "readOnly": false, "listItems": ["none","vyos01","vyos02","vyos03"],"defaultValue":"none"},"saveComment":"added by autoProv.py"}'
        sess.post(configuration['url'] + 'AddPropertyDefinition', auth=(username, password), headers=headers,
                  data=param, verify=configuration['validateCert'])


def deleteObject(ref):
    theres = sess.post(configuration['url'] + 'RemoveObject?ref=%s' % (ref), auth=(username, password), headers=headers, data=param, verify=configuration['validateCert'])
    logger.info("Deleting object: %s" % ( theres ))

def getIPAMRef(IP):
    theres = sess.get(configuration['url'] + 'GetIPAMRecord?addrRef=%s' % (IP), auth=(username, password), headers=headers, data=param, verify=configuration['validateCert'])
    if theres.ok:
        return theres.json()['result']['ipamRecord']['addrRef']
    else:
        return "None"
def addDnsRecord(name, IP, zoneRef):
    param = '{"dnsRecords": [{"name": "%s", "type": "A", "data": "%s", "enabled":true, "comment": "Added by autoProv.py", "dnsZoneRef": "%s"}]}' % (name, IP, zoneRef)
    theres = sess.post(configuration['url'] + 'AddDnsRecords', auth=(username, password), headers=headers, data=param, verify=configuration['validateCert'])
    if theres.ok :
        logger.info("Created DNS Entry %s for %s" % ( name, IP))
    else:
        logger.error("Failed to create DNS Entry. theres returned %s" % (theres.json()))


def updateProvStatus(ref, status):
    param = '{"ref": "%s", "properties": {"auto-provision": "%s"}}' % (ref, status)
    theres = sess.post(configuration['url'] + 'SetProperties', auth=(username, password), headers=headers, data=param, verify=configuration['validateCert'])


def hasCustomProperty(objectType, name):
    param = '{"objType": "%s"}' % (objectType)
    theRes = sess.get(configuration['url'] + 'GetPropertyDefinitions', auth=(username, password), headers=headers, data=param, verify=configuration['validateCert'])
    for property in theRes.json()['result']['propertyDefinitions']:
        if property['name'] == name:
            return True
    return False


def getIPAMData(provisionGrp):
    ipamData = {}
    theres = sess.get(configuration['url'] + 'GetIPAMTreeFragment?filter=provision-grp=%s&flat=true' % (provisionGrp), auth=(username, password), headers=headers, data=param, verify=configuration['validateCert'])
    try:
        for ipamRange in theres.json()['result']['ranges']:
            rangeRef = ipamRange["ref"]
            ipamData[rangeRef] = {"name": ipamRange["name"],"network": ipamRange['name'].split('/')[0], "netMask": ipamRange['name'].split('/')[1], "auto-provision": ipamRange["customProperties"]["auto-provision"], "provision-grp": ipamRange["customProperties"]["provision-grp"], "firstIP": str(list(ipaddress.ip_network(ipamRange["name"]).hosts())[0]), "lastIP": str(list(ipaddress.ip_network(ipamRange["name"]).hosts())[-1])}
    except Exception as e:
        logger.error(e)
    return ipamData

def genPassword(length=12):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choices(characters, k=length))
    return password


def createFernetUserIfNeeded(userName):
    theRes = sess.get(configuration['url'] + "getUsers?filter=%s" % (userName), auth=(username, password),
                      headers=headers, verify=configuration['validateCert'])
    if len(theRes.json()['result']['users']) > 0:
        return
    else:
        logger.info("Fernet user is missing and needs to be created")
        userPass = genPassword()
        param = '{"user":{"name": "%s", "password": "%s", "fullName": "Fernet keystore", "authenticationType": "Internal", "email" : "", "description" : "", "groups" : [], "roles" : [] }}' % ( userName, userPass)
        sess.post(configuration['url'] + "AddUser", auth=(username, password), headers=headers, data=param,
                  verify=configuration['validateCert'])


def createKey(uRef):
    fKey = Fernet.generate_key().decode("utf-8")
    param = '{"ref": "%s", "properties": {"description": "%s"}}' % (uRef, fKey)
    theRes = sess.post(configuration['url'] + 'SetProperties',
                       auth=(username, password), headers=headers, data=param,
                       verify=configuration['validateCert'])
    if theRes:
        logger.info("Successfully updated %s account description with fernetKey" % (fernetUser))
    else:
        logger.error('Failed to update %s with fernetKey' % (fernetUser))
    return theRes, fKey


def checkKey(micetroUser):
    # Connect to Micetro and pull back the contents of the description field associated with
    # the 'fernetUser' user account. This field contains the Fernet Key used for encryption/decryption
    theRes = sess.get(configuration['url'] + "GetUsers?filter=" + micetroUser,
                      auth=(username, password), headers=headers,
                      verify=configuration['validateCert'])
    if theRes.json()['result']['totalResults'] > 0:
        # user account must exist, getting the contents of the description field
        logger.info("Retrieving key from %s user description field" % (fernetUser))
        fKey = theRes.json()['result']['users'][0]['description']
        userRef = theRes.json()['result']['users'][0]['ref']
    else:
        logger.error("Failed to retrieve key from external user description field. does the user %s exist?",
                     micetroUser)
    return fKey, userRef


def encryptCred(key, credential):
    f = Fernet(key)
    # prefix encrKey with ENCRYPTION_PREFIX + '#' so we can identify encrypted data easily
    encrString = ENCRYPTION_PREFIX + "#" + f.encrypt(str.encode(credential)).decode("utf-8")
    return encrString


def decryptCred(key, credential):
    f = Fernet(key)
    try:
        decryptString = str(f.decrypt(bytes(credential.split('#', 2)[1], "utf8")), 'utf-8')
    except:
        logger.error("Failed to decrypt credential using Fernet. Was this encrypted using a different Fernet key?")
        return False
    return decryptString


def isEncrypted(secret):
    return secret.split('#', 2)[0] == ENCRYPTION_PREFIX


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='An external network discovery engine for Micetro')
    parser.add_argument('-u', type=str, metavar="username", help='username to login to Micetro', default=os.getlogin())
    parser.add_argument('-p', type=str, metavar="password", help='password to login to Micetro', default='')
    parser.add_argument('-v', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('arguments_from_micetro', nargs='*', type=str, help='If %(prog)s is being called from Micetro')
    args = parser.parse_args()

    if args.arguments_from_micetro:
        username = args.arguments_from_micetro[0]
        password = args.arguments_from_micetro[1]
        scriptPath = 'scripts/'
    else:
        username = args.u
        password = args.p
        scriptPath = ''

    with open(scriptPath + 'autoProvSetup.json') as f:
        configuration = json.load(f)
        configuration['v2url'] = configuration['url'].replace('command', 'v2')

    # configure logging
    logger = logging.getLogger('men_and_mice_api_logger')
    # Read LogLevel from setuo
    # 10 - DEBUG
    # 20 - INFO
    # 30 - WARNING
    # 40 - ERROR
    # 50 - CRITICAL
    logger.setLevel(configuration['logLevel'])
    handler = logging.handlers.RotatingFileHandler(configuration['logFileName'],
                                                   maxBytes=configuration['logFileSizeInBytes'],
                                                   backupCount=configuration['logFileBackupCount'])
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info("Starting Auto Provisioning v %s" % (__version__))
    logger.debug("Starting autoProvSetup.json format check v %s" % (__version__))
    logger.debug("Connecting to %s" % (configuration['url']))

    param = ""
    theRes = sess.get(configuration['url'] + 'Login', auth=(username, password), headers=headers, data=param,
                      verify=configuration['validateCert'])
    logger.debug("Got response %s from Micetro API" % (theRes))
    logger.debug("API test returned %s" % (theRes.json()))
    logger.debug("creds %s %s" % (username, password))
    logger.debug("Finished autoProvSetup.json check")

    try:
        # add missing Custom Properties (if required)
        createMissingCustomFields()

        logger.info("Parsing autoProvGroups.json")
        with open(scriptPath + 'autoProvGroups.json') as f:
            provGroups = json.load(f)

        # Check to see if we should be encrypting credentials
        fernetKey = ""
        if configuration['encryptAuth']:
            fernetUser = configuration['fernetUser']
            createFernetUserIfNeeded(configuration['fernetUser'])
            logger.info(
                "Checking to see if we have an encryption key stored in the Description Field of %s" % (fernetUser))
            fernetKey, userRef = checkKey(fernetUser)
            if fernetKey:
                logger.info("Fernet encryption key found")
            else:
                logger.info(
                    "encryption key not found but we've been asked to encrypt credentials. Creating new Fernet key")
                result, fernetKey = createKey(userRef)
                if result:
                    logger.info("Successfully Created new Fernet key")
                else:
                    logger.error("Failed to create New Fernet key..")
        needToUpdateProvGroups = False

        # Do we want to add an A/PTR for the router interfaces created?
        updateDNS = False
        rZoneRef = ""
        if configuration['zone2addRouterInterfaceNamesToIfReq']:
            theZone = sess.get(configuration['url'] + 'GetDNSZones?filter=%s Master' % (configuration['zone2addRouterInterfaceNamesToIfReq']), auth=(username, password), headers=headers, verify=configuration['validateCert'])
            if theZone.json()['result']['totalResults'] == 1:
                updateDNS = True
                rZoneRef = theZone.json()['result']['dnsZones'][0]['ref']


        if 'provGroups' in provGroups:
            for provGroup in provGroups['provGroups']:
                if 'enabled' in provGroup and provGroup['enabled']:
                    logger.info("Processing Provisioning Group Profile: %s" % (provGroup['provGroup']))
                    deviceType = provGroup['deviceType']
                    match deviceType:
                        case "vyos":
                            logger.info("Looking for Networks related to deviceGroup %s" % provGroup['provGroup'])
                            vRanges = getIPAMData(provGroup['provGroup'])

                            # Check to see if we should be encrypting keys
                            apiKey = provGroup['key']
                            if configuration['encryptAuth']:
                                # Check to see if the key is already encrypted. In which case decrypt
                                if isEncrypted(apiKey):
                                    logger.debug("decrypting API keys for %s" % ( provGroup['provGroup'] ))
                                    apiKey = decryptCred(fernetKey, provGroup['key'])
                                else:
                                    # Encrypt the key and store in the profile
                                    logger.debug("encrypting API keys for %s" % (provGroup['provGroup']))
                                    # Set needToUpdateProvGroups to true (will write back the JSON) and insert the encrypted key
                                    needToUpdateProvGroups = True
                                    provGroup['key'] = encryptCred(fernetKey, apiKey)

                            # Setup connection to the vios API
                            logger.debug("Setting up connection to vyos router: %s " % ( provGroup['IP'] ))
                            vDevice = VyDevice(hostname=provGroup['IP'], apikey=apiKey, port=443, protocol="https", verify=False)

                            for vRange in vRanges:
                                logger.debug("Processing Micetro Range Reference %s" % ( vRange ))

                                if configuration["gateway"] == "firstIP":
                                    gateway = vRanges[vRange]["firstIP"]
                                else:
                                    gateway = vRanges[vRange]["lastIP"]
                                iName = provGroup["interfacePrefix"] + vRange.split('/')[1]

                                # add a network to vyos
                                if vRanges[vRange]['auto-provision'] == "add":
                                    logger.info("Adding Network %s to %s using gateway IP %s and interface name %s" % ( vRanges[vRange]["name"], vRanges[vRange]["provision-grp"], gateway, iName) )
                                    try:
                                        vResponse = vDevice.configure_set(path=["interfaces", "dummy", iName, "address", gateway + "/" + vRanges[vRange]["netMask"]])
                                        # set protocols static arp interface dum3356 address 10.222.2.1 mac aa:12:33:44:55:66
                                        v2Response = vDevice.configure_set(path=["interfaces", "dummy", iName, "description", "added by autoProv.py"])

                                        if not vResponse.error or v2Response.error:
                                            logger.info("vyos API returned: %s" % ( vResponse ))
                                            logger.info("vyos API returned %s" % (v2Response))
                                            # Now set the Custom Property to Active
                                            updateProvStatus(str(vRange), "provisioned")
                                            # Now add an A record if we've been asked to
                                            if updateDNS:
                                                addDnsRecord(iName, gateway, rZoneRef)
                                        else:
                                            logger.error("vyos API returned error: %s" % (vResponse.error))
                                    except Exception as e:
                                        logger.error(e)

                                # delete a network from vyos
                                if vRanges[vRange]['auto-provision'] == "delete":
                                    logger.info("Deleting Network %s from %s using gateway IP %s and interface name %s" % ( vRanges[vRange]["name"], vRanges[vRange]["provision-grp"], gateway, iName) )
                                    try:
                                        vResponse = vDevice.configure_delete(path=["interfaces", "dummy", iName])
                                        if not vResponse.error:
                                            logger.info("vyos API returned: %s" % ( vResponse.result ))
                                            # So now remove from Micetro
                                            logger.info("Checking and deleting any records associated with %s" % ( gateway))
                                            # check for associated IPAM records
                                            addrRef = getIPAMRef(gateway)
                                            if addrRef != "None":
                                                logger.info("Deleting IPAM object ref: %s" % (addrRef))
                                                deleteObject(addrRef)
                                            else:
                                                logger.debug("Nothing to delete")
                                            logger.info("deleting Network %s from Micetro" % (vRanges[vRange]["name"]))
                                            deleteObject(vRange)


                                        else:
                                            logger.error("vyos API returned error: %s" % (vResponse.error))
                                    except Exception as e2:
                                        logger.error(e2)

                                # Check to see if a network is active
                                if vRanges[vRange]['auto-provision'] == "provisioned":
                                    logger.info("Network %s to %s using gateway IP %s and interface name %s should be already active" % ( vRanges[vRange]["name"], vRanges[vRange]["provision-grp"], gateway, iName) )
                                    try:
                                        vResponse = vDevice.show(path=["interfaces", "dummy", iName])
                                        if not vResponse.error:
                                            logger.info("vyos API returned: %s" % ( str(vResponse.result).split()))
                                            #logger.debug("vyos API returned: %s" % ( vResponse.result ))
                                        else:
                                            logger.error("vyos API returned error: %s" % (vResponse.error))
                                    except Exception as e3:
                                        logger.error(e3)

                                # Nothing to do
                                if vRanges[vRange]['auto-provision'] == "none":
                                    logger.info("No action required for Network %s" % ( vRanges[vRange]["name"] ) )

                            # save changes to vyos
                            logger.info("Saving Changes to vyos host %s IP %s" % (provGroup["provGroup"], provGroup["IP"]))
                            try:
                                vSave = vDevice.config_file_save()
                            except Exception as e4:
                                logger.error(e4)

                        case _:
                            logger.error("deviceType %s is not currently supported by this script" % (deviceType))

            # Check to see if we've encrypted any API keys and therefore need to update the config
            if needToUpdateProvGroups:
                logger.info("JSON data has been updated. Updating autoProvGroups.json")
                with open(scriptPath + 'autoProvGroups.json', 'w') as f:
                    json.dump(provGroups, f, indent=4)
    except Exception as e:
        logger.error("Exception generated %s" % (e))
    logger.info("Finished")
# End