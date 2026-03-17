autoProv.py is a Python based script written as an example to show how Micetro can be used for Network Automation

It does this by querying Micetro via the JSON-RPC/SOAP API ( https://docs.bluecatnetworks.com/r/en-US/Micetro-User-Guide/SOAP-API-for-Micetro/25.2.0) for Ranges that have the Custom Property ‘provision-grp’, defined matching the router profile defined in the configuration file autoProvGroups.json
The value of another custom property set at the Range level ‘auto-provision’ is then read and the following actions taken accordingly –

add        -->  The network interface is added to the target router defined in ‘provision-grp’
delete     -->  The network interface is removed from the target router and the range is deleted from Micetro
none       -->  No action is taken
provisioned-->  The network was previously successfully provisioned. The script will run some checks

This was written as an example and as such only works against VyOS routers using the VyOS api. However, the coded and config is structured such that this could easily be modified to work with other routers/switches/firewalls

I hope you find this useful… 
