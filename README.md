Get network gateway which equals to the router
Scan nmap -sn = all clients and access points in the network

Get our computer's local connected access point
Extract metadata (mac_prefix, vendor, response_time)

Filter all device that respond with there header by assuming they are IOT devices

Check for all ips in the net if there mac contains the same mac_prefix and vendor as our access point
if so that ip is labeled as an access point and stored for future sessions

then we plot for all ips and access point's response_time in a dot plot
for all clusters in that dot plot that have an access point as one of its values
will be considered a access point segmented part of the network
and all ips in the cluster will be considered clients except the access point that respresents it
