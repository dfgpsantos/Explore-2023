################################################################################
#
# This configuration file is an example of creating a full-fledged 3-Tier App
# using Terraform.
#
# It creates the following objects:
#   - Tier-1 Gateway (that gets attached to an existing Tier-0 Gateway)
#   - A DHCP Server providing DHCP Addresses to all 3 Segments
#   - 3 Segments (Web, App, DB)
#   - Dynamic Groups based on VM Tags
#   - Static Group based on IP Addresses
#   - Distributed Firewall Rules
#   - Services
#   - VM tags
#
# The config has been validated against:
#    NSX-T 4.1 using NSX-T Terraform Provider v3.3
#
# The config below requires the following to be pre-created
#   - Edge Cluster
#   - Overlay Transport Zone
#   - Tier-0 Gateway
#
# It also uses these 3 Services available by default on NSX-T
#   - HTTPS
#   - MySQL
#   - SSH
#
# The configuration also assumes the following Virtual Machines (VMs)
# are available through the vCenter (Compute Manager) Inventory. Assignment
# of the Virtual Machine network to the Segments provided is done outside
# the scope of this example
#   - web-VM
#   - app-VM
#   - db-VM
#
################################################################################


#
# The first step is to configure the VMware NSX provider to connect to the NSX
# REST API running on the NSX manager.
#
provider "nsxt" {
#  version               = "~> 3.1.1"
  host                  = var.nsx_manager
  username              = var.nsx_username
  password              = var.nsx_password
  allow_unverified_ssl  = true
  max_retries           = 10
  retry_min_delay       = 500
  retry_max_delay       = 5000
  retry_on_status_codes = [429]
}

#
# Here we show that you define a NSX tag which can be used later to easily to
# search for the created objects in NSX.
#
variable "nsx_tag_scope" {
  default = "project"
}

variable "nsx_tag" {
  default = "terraform-demo"
}


#
# This part of the example shows some data sources we will need to refer to
# later in the .tf file. They include the transport zone, tier 0 router and
# edge cluster.
# There Tier-0 (T0) Gateway is considered a "provider" router that is pre-created
# by the NSX Admin. A T0 Gateway is used for north/south connectivity between
# the logical networking space and the physical networking space. Many Tier1
# Gateways will be connected to the T0 Gateway
#
data "nsxt_policy_edge_cluster" "demo" {
  display_name = "EdgeCluster"
}

data "nsxt_policy_transport_zone" "overlay_tz" {
  display_name = "nsx-overlay-transportzone"
}

data "nsxt_policy_tier0_gateway" "t0_gateway" {
  display_name = "T0"
}

#
# Create a DHCP Profile that is used later
# Note, this resource is only in NSX 3.0.0+
resource "nsxt_policy_dhcp_server" "tier_dhcp" {
  display_name     = "tier_dhcp"
  description      = "DHCP server servicing all 3 Segments"
  server_addresses = ["172.16.254.2/30"]
}

#
# In this part of the example, the settings required to create a Tier1 Gateway
# are defined. In NSX a Tier1 Gateway is often used on a per user, tenant,
# department or application basis. Each application may have it's own Tier1
# Gateway. The Tier1 Gateway provides the default gateway for virtual machines
# connected to the Segments on the Tier1 Gateway
#
resource "nsxt_policy_tier1_gateway" "t1_gateway" {
  display_name              = "Explore2023-T1-TF"
  description               = "Tier1 provisioned by Terraform"
  edge_cluster_path         = data.nsxt_policy_edge_cluster.demo.path
  dhcp_config_path          = nsxt_policy_dhcp_server.tier_dhcp.path
  failover_mode             = "PREEMPTIVE"
  default_rule_logging      = "false"
  enable_firewall           = "true"
  enable_standby_relocation = "false"
  tier0_path                = data.nsxt_policy_tier0_gateway.t0_gateway.path
  route_advertisement_types = ["TIER1_STATIC_ROUTES", "TIER1_CONNECTED"]
  pool_allocation           = "ROUTING"

  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }

}

#
# This shows the settings required to create NSX Segment (Logical Switch) to
# which you can attach Virtual Machines (VMs)
#
resource "nsxt_policy_segment" "web" {
  display_name        = "Explore2023-web-tier-tf"
  description         = "Terraform provisioned Web Segment"
  connectivity_path   = nsxt_policy_tier1_gateway.t1_gateway.path
  transport_zone_path = data.nsxt_policy_transport_zone.overlay_tz.path

  subnet {
    cidr        = "172.191.11.1/24"
    dhcp_ranges = ["172.191.11.20-172.191.11.240"]

    dhcp_v4_config {
      server_address = "172.16.254.2/24"
      lease_time     = 36000

      dhcp_option_121 {
        network  = "0.0.0.0/0"
        next_hop = "172.191.11.1"
      }
    }
  }

  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
  tag {
    scope = "tier"
    tag   = "web-tf"
  }
}

resource "nsxt_policy_segment" "app" {
  display_name        = "Explore2023-app-tier-tf"
  description         = "Terraform provisioned App Segment"
  connectivity_path   = nsxt_policy_tier1_gateway.t1_gateway.path
  transport_zone_path = data.nsxt_policy_transport_zone.overlay_tz.path

  subnet {
    cidr        = "172.191.12.1/24"
    dhcp_ranges = ["172.191.12.20-172.191.12.240"]

    dhcp_v4_config {
      server_address = "172.16.254.2/30"
      lease_time     = 36000

      dhcp_option_121 {
        network  = "0.0.0.0/0"
        next_hop = "172.191.12.1"
      }
    }
  }

  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
  tag {
    scope = "tier"
    tag   = "app-tf"
  }
}

resource "nsxt_policy_segment" "db" {
  display_name        = "Explore2023-db-tier-tf"
  description         = "Terraform provisioned DB Segment"
  connectivity_path   = nsxt_policy_tier1_gateway.t1_gateway.path
  transport_zone_path = data.nsxt_policy_transport_zone.overlay_tz.path

  subnet {
    cidr        = "172.191.13.1/24"
    dhcp_ranges = ["172.191.13.30-172.191.13.240"]

    dhcp_v4_config {
      server_address = "172.16.254.2/30"
      lease_time     = 36000

      dhcp_option_121 {
        network  = "0.0.0.0/0"
        next_hop = "172.191.13.1"
      }
    }
  }

  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
  tag {
    scope = "tier"
    tag   = "db-tf"
  }
}

#
# This part of the example shows creating Groups with dynamic membership
# criteria
#
# All Virtual machines with specific tag and scope
resource "nsxt_policy_group" "all_vms" {
  display_name = "Explore2023_All_VMs-tf"
  description  = "Group consisting of ALL VMs"
  criteria {
    condition {
      member_type = "VirtualMachine"
      operator    = "CONTAINS"
      key         = "Tag"
      value       = var.nsx_tag

    }
  }
}

# All WEB VMs
resource "nsxt_policy_group" "web_group" {
  display_name = "Explore2023_Web-VMs-tf"
  description  = "Group consisting of Web VMs"
  criteria {
    condition {
      member_type = "VirtualMachine"
      operator    = "CONTAINS"
      key         = "Tag"
      value       = "web-tf"
    }
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

# All App VMs
resource "nsxt_policy_group" "app_group" {
  display_name = "Explore2023_App-VMs-tf"
  description  = "Group consisting of App VMs"
  criteria {
    condition {
      member_type = "VirtualMachine"
      operator    = "CONTAINS"
      key         = "Tag"
      value       = "app-tf"
    }
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

# All DB VMs
resource "nsxt_policy_group" "db_group" {
  display_name = "Explore2023_DB-VMs-tf"
  description  = "Group consisting of DB VMs"
  criteria {
    condition {
      member_type = "VirtualMachine"
      operator    = "CONTAINS"
      key         = "Tag"
      value       = "db-tf"
    }
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

# Static Group of IP addresses
resource "nsxt_policy_group" "ip_set" {
  display_name = "Explore2023-external-IPs-tf"
  description  = "Group containing all external IPs"
  criteria {
    ipaddress_expression {
      ip_addresses = ["211.1.1.1", "212.1.1.1", "192.168.250.1-192.168.250.100"]
    }
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

#
# An example for Service for App that listens on port 8443
#
resource "nsxt_policy_service" "app_service" {
  display_name = "Explore2023_app_service_8443"
  description  = "Service for App that listens on port 8443"
  l4_port_set_entry {
    description       = "TCP Port 8443"
    protocol          = "TCP"
    destination_ports = ["8443"]
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

#
# Here we have examples of create data sources for Services
#
data "nsxt_policy_service" "https" {
  display_name = "HTTPS"
}

data "nsxt_policy_service" "mysql" {
  display_name = "MySQL"
}

data "nsxt_policy_service" "ssh" {
  display_name = "SSH"
}


#
# In this section, we have example to create Firewall sections and rules
# All rules in this section will be applied to VMs that are part of the
# Gropus we created earlier
#
resource "nsxt_policy_security_policy" "firewall_section" {
  display_name = "Explore2023 DFW Section tf"
  description  = "Firewall section created by Terraform"
  scope        = [nsxt_policy_group.all_vms.path]
  category     = "Application"
  locked       = "false"
  stateful     = "true"

  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }

# Allow communication to any VMs only on the ports defined earlier

  rule {
    display_name       = "Block SSH Web"
    description        = "In going rule"
    action             = "DROP"
    logged             = "false"
    ip_version         = "IPV4"
    source_groups      = [nsxt_policy_group.web_group.path]
    destination_groups = [nsxt_policy_group.web_group.path]
    services           = [data.nsxt_policy_service.ssh.path]
  }

  rule {
    display_name       = "Allow HTTPS"
    description        = "In going rule"
    action             = "ALLOW"
    logged             = "true"
    ip_version         = "IPV4"
    destination_groups = [nsxt_policy_group.web_group.path]
    services           = [data.nsxt_policy_service.https.path]
  }

  # Web to App communication
  rule {
    display_name       = "Allow Web to App"
    description        = "Web to App communication"
    action             = "ALLOW"
    logged             = "true"
    ip_version         = "IPV4"
    source_groups      = [nsxt_policy_group.web_group.path]
    destination_groups = [nsxt_policy_group.app_group.path]
    services           = [nsxt_policy_service.app_service.path]
  }

  # App to DB communication
  rule {
    display_name       = "Allow App to DB"
    description        = "App to DB communication"
    action             = "ALLOW"
    logged             = "true"
    ip_version         = "IPV4"
    source_groups      = [nsxt_policy_group.app_group.path]
    destination_groups = [nsxt_policy_group.db_group.path]
    services           = [data.nsxt_policy_service.mysql.path]
  }

  # Allow External IPs to communicate with VMs
  rule {
    display_name       = "Allow Infrastructure"
    description        = "Allow DNS and Management servers"
    action             = "ALLOW"
    logged             = "true"
    ip_version         = "IPV4"
    source_groups      = [nsxt_policy_group.ip_set.path]
    destination_groups = [nsxt_policy_group.all_vms.path]
  }

  # Allow VMs to communicate with outside
  rule {
    display_name  = "Allow out"
    description   = "Outgoing rule"
    action        = "ALLOW"
    logged        = "true"
    ip_version    = "IPV4"
    source_groups = [nsxt_policy_group.all_vms.path]
  }

  # Reject everything else
  rule {
    display_name = "Deny ANY"
    description  = "Default Deny the traffic"
    action       = "REJECT"
    logged       = "true"
    ip_version   = "IPV4"
    destination_groups = [nsxt_policy_group.all_vms.path]
  }
}

#The 4 VMs available in the NSX Inventory
data "nsxt_policy_vm" "web_vm1" {
  display_name = "web-01a"
}

data "nsxt_policy_vm" "web_vm2" {
  display_name = "web-02a"
}

data "nsxt_policy_vm" "app_vm" {
  display_name = "app-01a"
}

data "nsxt_policy_vm" "db_vm" {
  display_name = "db-01a"
}


#Assign the right tags to the VMs so that they get included in the dynamic groups created above
resource "nsxt_policy_vm_tags" "web_vm_tag1" {
  instance_id = data.nsxt_policy_vm.web_vm1.instance_id
  tag {
    scope = "tier"
    tag   = "web-tf"
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

resource "nsxt_policy_vm_tags" "web_vm_tag2" {
  instance_id = data.nsxt_policy_vm.web_vm2.instance_id
  tag {
    scope = "tier"
    tag   = "web-tf"
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

resource "nsxt_policy_vm_tags" "app_vm_tag" {
  instance_id = data.nsxt_policy_vm.app_vm.instance_id
  tag {
    scope = "tier"
    tag   = "app-tf"
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}

resource "nsxt_policy_vm_tags" "db_vm_tag" {
  instance_id = data.nsxt_policy_vm.db_vm.instance_id
  tag {
    scope = "tier"
    tag   = "db-tf"
  }
  tag {
    scope = var.nsx_tag_scope
    tag   = var.nsx_tag
  }
}
