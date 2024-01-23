#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
Prommetrix - Tool to obtain relevant information from the instances of 'Node Exporter' executed by 'Prometheus' - 2024 - by psy (https://03c8.net)

----------

Prometheus is an open-source, metrics-based event monitoring and alerting solution for cloud applications. It is used by nearly 800 cloud-native organizations including Uber, Slack, Robinhood, and more. By scraping real-time metrics from various endpoints, Prometheus allows easy observation of a system’s state in addition to observation of hardware and software metrics such as memory usage, network usage and software-specific defined metrics (ex. number of failed login attempts to a web application).

 - https://prometheus.io/docs/guides/node-exporter/

Since the numeric metrics captured by Prometheus are not considered sensitive data, Prometheus has held an understandable policy of avoiding built-in support for security features such as authentication and encryption, in order to focus on developing the monitoring-related features. This changed less than a year ago (Jan 2021), on the release of version 2.24.0 where Transport Layer Security (TLS) and basic authentication support were introduced.

Due to the fact that authentication and encryption support is relatively new, many organizations that use Prometheus haven’t yet enabled these features and thus many Prometheus endpoints are completely exposed to the Internet (e.g. endpoints that run earlier versions), leaking metric and label data.

----------

This vulnerabily can be described in a Pentest/Report like: 

 - PRM-01-001 Client: Clients leak Metrics data through unprotected endpoint (LOW)

"Metric data are to be collected for some services and these items need to implement a
client-library that enables the core Prometheus service to scrape the data. The client-
library opens a minimal HTTP server and exposes a route which is then registered with
the core service for scraping. This endpoint is unauthenticated by default, which allows
anybody who knows the URI to read the metric data. It is recommended to put some
form of authentication in place. Only the core Prometheus service should be allowed to
read the metric data."

----------

Prommetrix - will take advantage of these metrics to obtain relevant information from the Prometheus instance, as well as, of the machine in which it is running.

[!] The information obtained can be used to build other types of attacks over the different pieces of software/versions exposed (ex: CVE).

----------

You should have received a copy of the GNU General Public License along
with Prommetrix; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
VERSION=str(0.1)

import os, sys, requests, random, re 

def banner():
    print(r'''Prommetrix (v'''+VERSION+''') by psy (https://03c8.net) | 2024

    Source Code:
    
      - Official: https://code.03c8.net/epsylon/prommetrix
      - Mirror: https://github.com/epsylon/prommetrix
      
    Usage: 
      
      python3 prommetrix.py --target <IP> --port <PORT> (default: 9100)
    ''')


def init():
    if "--target" in sys.argv:
        user_agent_list = [
    	    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
  	    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
  	    'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
	    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36 Edg/87.0.664.75',
  	    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363',
	]
        headers={"User-Agent": user_agent_list[random.randint(0, len(user_agent_list)-1)]}
        try:
            if "--port" in sys.argv:
                r = requests.get("http://"+sys.argv[2]+":"+sys.argv[4]+"/metrics", headers=headers) 
            else:
                r = requests.get("http://"+sys.argv[2]+":9100"+"/metrics", headers=headers)   
        except:
            print("")
            banner()
            sys.exit(2)       
        if r.status_code != 200:
            print("\n[ERROR] Not any 'Prometheus' have been detected <-> ABORTING!\n")
            banner()
            sys.exit(2)
        else:
            with open('tmp.txt','w') as fd:
                metrics= re.sub(r'^#.*\n?', '', r.text, flags=re.MULTILINE)
                fd.write(metrics)
        r_text = open("tmp.txt", "r").read()
        print("\n[INFO] 'Prometheus' detected at: "+sys.argv[2]+" <-> EXPOSING!\n")
        print("  - Metrics path:")
        print("     - URL: "+r.url)
        print("\n  - 'Go' (environment):")
        print("     - Version: "+r_text.split('go_info{version="')[1].split('"}')[0])
        node_exporter_build_branch = r_text.split('node_exporter_build_info{branch="')[1].split('"')[0]
        node_exporter_build_goversion = r_text.split('goversion="')[1].split('"')[0]
        node_exporter_build_revision = r_text.split('revision="')[1].split('"')[0]
        node_exporter_build_version = r_text.split('version="')[1].split('"')[0]      
        node_dmi_bios_date = r_text.split('node_dmi_info{bios_date="')[1].split('"')[0]
        node_dmi_bios_release = r_text.split('bios_release="')[1].split('"')[0]
        node_dmi_bios_version = r_text.split('bios_version="')[1].split('"')[0]
        node_dmi_bios_vendor = r_text.split('bios_vendor="')[1].split('"')[0]                  
        node_os_build = r_text.split('node_os_info{build_id="')[1].split('",id')[0]
        node_os_id = r_text.split(',id="')[1].split('",id_like')[0]
        node_os_id_like = r_text.split('id_like="')[1].split('",image_id')[0]
        node_os_image_id = r_text.split('image_id="')[1].split('",image_version')[0]
        node_os_image_version = r_text.split('image_version="')[1].split('",name')[0]
        node_os_name = r_text.split(',name="')[1].split('",pretty_name')[0]
        node_os_pretty_name = r_text.split('pretty_name="')[1].split('",variant')[0]
        node_os_variant = r_text.split('variant="')[1].split('",variant_id')[0] 
        node_os_variant_id = r_text.split('variant_id="')[1].split('",version')[0]  
        node_os_version_codename = r_text.split('version_codename="')[1].split('",version_id')[0]
        node_os_version_id = r_text.split('version_id="')[1].split('"}')[0]                                   
        node_dmi_board_asset_tag = r_text.split('board_asset_tag="')[1].split('"')[0]
        node_dmi_board_name = r_text.split('board_name="')[1].split('"')[0]
        node_dmi_board_version = r_text.split('board_version="')[1].split('"')[0]
        node_dmi_board_vendor = r_text.split('board_vendor="')[1].split('"')[0]
        node_dmi_chassis_asset_tag = r_text.split('chassis_asset_tag="')[1].split('"')[0]
        node_dmi_chassis_version = r_text.split('chassis_version="')[1].split('"')[0]
        node_dmi_chassis_vendor = r_text.split('chassis_vendor="')[1].split('"')[0]
        node_dmi_product_family = r_text.split('product_family="')[1].split('"')[0]
        node_dmi_product_name = r_text.split('product_name="')[1].split('"')[0]
        node_dmi_product_sku = r_text.split('product_sku="')[1].split('"')[0]
        node_dmi_product_version = r_text.split('product_version="')[1].split('"')[0]
        node_dmi_system_vendor = r_text.split('system_vendor="')[1].split('"')[0]       
        node_cpus = r_text.split('node_softnet_dropped_total{cpu="')           
        node_uname_info_domainname = r_text.split('node_uname_info{domainname="')[1].split('"')[0]
        node_uname_info_machine = r_text.split('machine="')[1].split('",nodename')[0]
        node_uname_info_nodename = r_text.split('nodename="')[1].split('",release')[0]
        node_uname_info_release = r_text.split(',release="')[1].split('",sysname')[0]     
        node_uname_info_sysname = r_text.split(',sysname="')[1].split('",version')[0]            
        node_uname_info_version = r_text.split('version="#')[1].split('"} ')[0]   
        node_time_zone = r_text.split('node_time_zone_offset_seconds{time_zone="')[1].split('"')[0]                   
        print("\n  - 'Node Export' (build):")    
        if node_exporter_build_branch:
            print("     - Branch: "+node_exporter_build_branch)   
        if node_exporter_build_goversion:   
            print("     - Go Version: "+node_exporter_build_goversion) 
        if node_exporter_build_revision:        
            print("     - Revision: "+node_exporter_build_revision)   
        if node_exporter_build_version:      
            print("     - Version: "+node_exporter_build_version)   
        if node_cpus:  
            print("\n  - CPUs (total):")  
            node_cpus_number = 0 
            for d in node_cpus[1:]:
                node_cpus_number = node_cpus_number + 1             
            print("     - "+str(node_cpus_number))  
        print("\n  - SYSTEM:")   
        if node_dmi_system_vendor:   
            print("     - Vendor: "+node_dmi_system_vendor)
        print("\n  - BIOS:")   
        if node_dmi_bios_date:   
            print("     - Date: "+node_dmi_bios_date)
        if node_dmi_bios_release:   
            print("     - Release: "+node_dmi_bios_release)
        if node_dmi_bios_vendor:   
            print("     - Vendor: "+node_dmi_bios_vendor)
        if node_dmi_bios_version:   
            print("     - Version: "+node_dmi_bios_version)
        print("\n  - OS:") 
        if node_os_build:   
            print("     - Build ID: "+node_os_build)
        if node_os_id:   
            print("     - ID: "+node_os_id)
        if node_os_id_like:   
            print("     - ID Like: "+node_os_id_like)
        if node_os_image_id:   
            print("     - Image ID: "+node_os_image_id)
        if node_os_image_version:   
            print("     - Image version: "+node_os_image_version)
        if node_os_name:   
            print("     - Name: "+node_os_name)
        if node_os_pretty_name:   
            print("     - Pretty name: "+node_os_pretty_name)   
        if node_os_variant:   
            print("     - Variant: "+node_os_variant)
        if node_os_variant_id:   
            print("     - Variant ID: "+node_os_variant_id) 
        if node_os_version_codename:   
            print("     - Version codename: "+node_os_version_codename)
        if node_os_version_id:   
            print("     - Version ID: "+node_os_version_id)    
        print("\n  - UNAME:")   
        if node_uname_info_domainname:   
            print("     - Domainname: "+node_uname_info_domainname)
        if node_uname_info_machine:   
            print("     - Machine: "+node_uname_info_machine)
        if node_uname_info_nodename:   
            print("     - Nodename: "+node_uname_info_nodename)
        if node_uname_info_release:   
            print("     - Release: "+node_uname_info_release)
        if node_uname_info_sysname:   
            print("     - Sysname: "+node_uname_info_sysname)            
        if node_uname_info_version:   
            print("     - Version: "+node_uname_info_version)
        if node_time_zone:
            print("\n  - TIMEZONE:")      
            print("     - Location: "+node_time_zone)     
        node_time_clocksource_available_info_devices = r_text.split('node_time_clocksource_available_info{clocksource="')   
        if node_time_clocksource_available_info_devices:  
            print("\n  - CLOCKSOURCE entries:")
            for d in node_time_clocksource_available_info_devices[1:]:
                node_time_clocksource_available_info_device = d.split(',device')[0].replace('"',"")
                print("     - "+node_time_clocksource_available_info_device)                                     
        print("\n  - BOARD:")   
        if node_dmi_board_asset_tag:   
            print("     - Asset_tag: "+node_dmi_board_asset_tag)
        if node_dmi_board_name:   
            print("     - Name: "+node_dmi_board_name)
        if node_dmi_board_vendor:   
            print("     - Vendor: "+node_dmi_board_vendor)
        if node_dmi_board_version:   
            print("     - Version: "+node_dmi_board_version)
        print("\n  - CHASSIS:")  
        if node_dmi_chassis_asset_tag:   
            print("     - Asset_tag: "+node_dmi_chassis_asset_tag)
        if node_dmi_chassis_vendor:   
            print("     - Vendor: "+node_dmi_chassis_vendor)
        if node_dmi_chassis_version:   
            print("     - Version: "+node_dmi_chassis_version)
        print("\n  - PRODUCT:")   
        if node_dmi_product_family:   
            print("     - Family: "+node_dmi_product_family)
        if node_dmi_product_name:  
            print("     - Name: "+node_dmi_product_name)
        if node_dmi_product_sku:  
            print("     - SKU: "+node_dmi_product_sku)
        if node_dmi_product_version:  
            print("     - Version: "+node_dmi_product_version)                           
        node_disk_info_devices = r_text.split('node_disk_info{device="')
        if node_disk_info_devices:  
            print("\n  - Info of /sys/block/<block_device>:")   
            for d in node_disk_info_devices[1:]:
                node_disk_info_device = d.split('"')[0]
                print("     - "+node_disk_info_device)   
        node_disk_filesystem_devices = r_text.split('node_filesystem_files_free{device="')
        if node_disk_filesystem_devices:  
            print("\n  - Info of node_filesystem_files:")   
            for d in node_disk_filesystem_devices[1:]:
                node_disk_filesystem_device = d.split('} ')[0].replace('"',"")
                print("     - "+node_disk_filesystem_device)
        node_network_iface_id_devices = r_text.split('node_network_iface_id{device="')
        if node_network_iface_id_devices:  
            print("\n  - NETWORK devices:")
            for d in node_network_iface_id_devices[1:]:
                node_network_iface_id_device = d.split('"')[0]
                print("     - "+node_network_iface_id_device)       
        node_network_info_devices = r_text.split('node_network_info{address="')
        if node_network_info_devices:  
            print("\n  - NETWORK entries by device:")
            for d in node_network_info_devices[1:]:
                node_network_info_device = d.split('} ')[0].replace('"',"")
                print("     - "+node_network_info_device)        
#        node_arp_devices = r_text.split('node_arp_entries{device="')
#        if node_arp_devices:  
#            print("\n  - ARP entries by device:")
#            for d in node_arp_devices[1:]:
#                arp_device = d.split('"')[0]
#                print("     - "+arp_device)         
        print("\n  - PROMETHEUS HTTP_metrics:")
        promhttp_metric_handler_errors_total_encoding = r_text.split('promhttp_metric_handler_errors_total{cause="encoding"}')[1].split("\n")[0]
        promhttp_metric_handler_errors_total_gathering = r_text.split('promhttp_metric_handler_errors_total{cause="gathering"}')[1].split("\n")[0]
        promhttp_metric_handler_requests_in_flight = r_text.split('promhttp_metric_handler_requests_in_flight')[1].split("\n")[0]
        promhttp_metric_handler_requests_total_200 = r_text.split('promhttp_metric_handler_requests_total{code="200"}')[1].split("\n")[0]
        promhttp_metric_handler_requests_total_500 = r_text.split('promhttp_metric_handler_requests_total{code="500"}')[1].split("\n")[0]
        promhttp_metric_handler_requests_total_503 = r_text.split('promhttp_metric_handler_requests_total{code="503"}')[1].split("\n")[0]
        print("      - HTTP-200 (OK)   : "+promhttp_metric_handler_requests_total_200)
        print("      - HTTP-500 (FAIL) : "+promhttp_metric_handler_requests_total_500)
        print("      - HTTP-503 (FAIL) : "+promhttp_metric_handler_requests_total_503)
        print("      - ENCODING (FAIL) : "+promhttp_metric_handler_errors_total_encoding)
        print("      - GHATERING (FAIL): "+promhttp_metric_handler_errors_total_gathering)
        print("")
    else:
        print("")
        banner()
    if os.path.exists("tmp.txt"):
        os.remove("tmp.txt")
init()
