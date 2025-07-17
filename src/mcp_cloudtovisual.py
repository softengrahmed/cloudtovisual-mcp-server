#!/usr/bin/env python3
"""
AWS Cloud to Diagram MCP Server - Procedural Version
This MCP server provides a tool to generate AWS architecture diagrams from deployed infrastructure.
It imports AWS resources using Terraformer and generates visual diagrams in PNG format.
"""

import json
import tempfile
import shutil
import os
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple

# MCP Server imports
from mcp.server.fastmcp import FastMCP

# Import diagrams library components
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EC2, Lambda, AutoScaling, ElasticBeanstalk
from diagrams.aws.database import RDS, Dynamodb
from diagrams.aws.storage import S3, EBS, EFS, S3Glacier
from diagrams.aws.network import VPC, PrivateSubnet, PublicSubnet, ELB, InternetGateway, NATGateway, VPCPeering, TransitGateway, DirectConnect, Route53, RouteTable
from diagrams.aws.integration import SNS, SQS
from diagrams.aws.security import IAM, KMS, SecurityIdentityAndCompliance
from diagrams.aws.management import Cloudwatch
from diagrams.aws.compute import ECR
from diagrams.aws.general import General, Users
from diagrams.aws.storage import StorageGateway

# Initialize MCP Server
mcp = FastMCP(
    name="AWS-CloudToDiagram", 
    description="MCP Server for generating AWS architecture diagrams from deployed cloud infrastructure using Terraformer import and visualization tools."
)

# Global configurations
CONTAINER_RESOURCES = {
    'aws_vpc', 'aws_subnet', 'aws_autoscaling_group', 'aws_ecs_cluster', 
    'aws_elastic_beanstalk_environment'
}

HIDDEN_RESOURCES = {
    'aws_eip'  # EIPs will be shown as labels on associated resources
}

VPC_LEVEL_RESOURCES = {
    'aws_internet_gateway', 'aws_vpc_peering_connection', 'aws_vpc_endpoint',
    'aws_security_group', 'aws_route_table', 'aws_network_acl'
}

SUBNET_LEVEL_RESOURCES = {
    'aws_instance', 'aws_nat_gateway', 'aws_ebs_volume', 'aws_network_interface',
    'aws_route_table_association'
}

# Mapping of Terraform resource types to diagram components
RESOURCE_MAPPING = {
    # Compute Resources
    'aws_instance': EC2,
    'aws_lambda_function': Lambda,
    'aws_elastic_beanstalk_application': ElasticBeanstalk,
    'aws_autoscaling_group': AutoScaling,
    
    # Database Resources
    'aws_db_instance': RDS,
    'aws_rds_cluster': RDS,
    'aws_dynamodb_table': Dynamodb,
    
    # Storage Resources
    'aws_s3_bucket': S3,
    'aws_ebs_volume': EBS,
    'aws_efs_file_system': EFS,
    'aws_glacier_vault': S3Glacier,
    'aws_storagegateway_gateway': StorageGateway,
    
    # Network Resources
    'aws_internet_gateway': InternetGateway,
    'aws_nat_gateway': NATGateway,
    'aws_vpc_peering_connection': VPCPeering,
    'aws_ec2_transit_gateway': TransitGateway,
    'aws_dx_connection': DirectConnect,
    'aws_lb': ELB,
    'aws_alb': ELB,
    'aws_elb': ELB,
    'aws_route_table': RouteTable,
    'aws_route': RouteTable,
    'aws_route_table_association': RouteTable,
    'aws_route53_zone': Route53,
    'aws_route53_record': Route53,
    'aws_vpc_endpoint': VPC,
    'aws_network_interface': EC2,
    
    # Container and Analytics
    'aws_ecr_repository': ECR,
    'aws_ecs_cluster': ECR,
    'aws_ecs_service': ECR,
    
    # Integration
    'aws_sns_topic': SNS,
    'aws_sqs_queue': SQS,
    
    # Security and IAM
    'aws_iam_user': IAM,
    'aws_iam_role': IAM,
    'aws_iam_group': IAM,
    'aws_iam_policy': IAM,
    'aws_kms_key': KMS,
    'aws_security_group': SecurityIdentityAndCompliance,
    'aws_network_acl': SecurityIdentityAndCompliance,
    
    # Monitoring and Management
    'aws_cloudwatch_log_group': Cloudwatch,
    'aws_cloudwatch_metric_alarm': Cloudwatch,
    
    # Data Sources
    'data.aws_vpc': VPC,
    'data.aws_subnet': PublicSubnet,
    'data.aws_subnets': PublicSubnet,
    'data.aws_security_group': SecurityIdentityAndCompliance,
    'data.aws_ami': EC2,
    'data.aws_availability_zones': General,
}

GLOBAL_SERVICES = {
    'aws_iam_user', 'aws_iam_role', 'aws_iam_group', 'aws_kms_key',
    'aws_cloudfront_distribution', 'aws_route53_zone', 'aws_route53_record'
}


def extract_resources( tfstate: Dict[str, Dict]) -> List[Dict[str, Any]]:
    #"""Extract resources from the flattened Terraform state."""
    resources = []
        
    # Iterate through the flattened resource dictionary
    # tfstate is now: {"resource_key": resource_data_dict, ...}
    for resource_key, resource_data in tfstate.items():
        # Extract resource type and name from the key (e.g., "aws_s3_bucket.my-bucket")
        if '.' in resource_key:
            resource_type, resource_name = resource_key.split('.', 1)
        else:
            resource_type = resource_data.get('type', resource_key)
            resource_name = resource_key
            
        # Extract attributes from the resource data
        attributes = {}
        if 'primary' in resource_data:
            # Terraform state v3 format
            attributes = resource_data.get('primary', {}).get('attributes', {})
        elif 'attributes' in resource_data:
            # Direct attributes format
            attributes = resource_data.get('attributes', {})
        elif 'instances' in resource_data:
            # If instances exist, take attributes from first instance
            instances = resource_data.get('instances', [])
            if instances and isinstance(instances, list) and len(instances) > 0:
                attributes = instances[0].get('attributes', {})
            
            # Determine mode (managed, data, etc.)
        mode = resource_data.get('mode', 'managed')
            
        # Extract provider information
        provider = resource_data.get('provider', '')
            
        # Append the extracted resource
        resources.append({
            'type': resource_type,
            'name': resource_name,
            'provider': provider,
            'attributes': attributes,
            'mode': mode
        })
        
    return resources


def process_eip_associations(resources: List[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """Process EIP associations to map them to their target resources."""
    eip_associations = {}
    
    for resource in resources:
        if resource['type'] == 'aws_eip':
            attrs = resource['attributes']
            instance_id = attrs.get('instance', '')
            network_interface_id = attrs.get('network_interface', '')
            public_ip = attrs.get('public_ip', '')
            
            target_resource = None
            if instance_id:
                target_resource = instance_id
            elif network_interface_id:
                target_resource = network_interface_id
            
            if target_resource:
                eip_associations[target_resource] = {
                    'public_ip': public_ip,
                    'eip_name': resource['name']
                }
    
    return eip_associations


def get_resource_region(resource: Dict[str, Any]) -> str:
    """Extract region from resource attributes."""
    attrs = resource['attributes']
    region = attrs.get('region', '')
    if not region:
        az = attrs.get('availability_zone', '')
        if az and len(az) > 1:
            region = az[:-1]
    return region if region else 'us-east-1'


def get_resource_label(resource: Dict[str, Any], eip_associations: Dict[str, Dict[str, str]]) -> str:
    """Generate a meaningful label for the resource."""
    name = resource['name']
    resource_type = resource['type']
    attrs = resource['attributes']
    
    # Try to get a descriptive name from tags or attributes
    tags = attrs.get('tags', {})
    if isinstance(tags, dict) and 'Name' in tags:
        base_label = f"{tags['Name']}"
    elif 'name' in attrs and attrs['name']:
        base_label = f"{attrs['name']}"
    else:
        clean_type = resource_type.replace('aws_', '').replace('_', ' ').title()
        base_label = f"{name}\n({clean_type})"
    
    # Add EIP information if available
    resource_id = attrs.get('id', '')
    if resource_id in eip_associations:
        eip_info = eip_associations[resource_id]
        public_ip = eip_info['public_ip']
        base_label += f"\nEIP: {public_ip}"
    
    return base_label


def organize_resources_by_hierarchy(resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Organize resources by their hierarchical placement."""
    hierarchy = {
        'global': [],
        'regions': defaultdict(lambda: {
            'regional': [],
            'vpcs': defaultdict(lambda: {
                'vpc_level': [],
                'subnets': defaultdict(lambda: {
                    'subnet_level': [],
                    'instances': []
                })
            })
        })
    }
    
    # First pass: identify VPCs and subnets
    actual_vpcs = {}
    actual_subnets = {}
    default_vpc_id = None
    
    for resource in resources:
        if resource['type'] == 'aws_vpc':
            vpc_id = resource['attributes'].get('id', resource['name'])
            actual_vpcs[vpc_id] = resource
            if resource['attributes'].get('default', False):
                default_vpc_id = vpc_id
        elif resource['type'] == 'aws_subnet':
            subnet_id = resource['attributes'].get('id', resource['name'])
            actual_subnets[subnet_id] = resource
    
    # Second pass: organize resources
    for resource in resources:
        resource_type = resource['type']
        attrs = resource['attributes']
        
        if resource_type in HIDDEN_RESOURCES:
            continue
        
        region = get_resource_region(resource)
        
        if resource_type in GLOBAL_SERVICES:
            hierarchy['global'].append(resource)
        elif resource_type == 'aws_vpc':
            vpc_id = attrs.get('id', resource['name'])
            hierarchy['regions'][region]['vpcs'][vpc_id]['vpc_resource'] = resource
        elif resource_type == 'aws_subnet':
            vpc_id = attrs.get('vpc_id', default_vpc_id)
            subnet_id = attrs.get('id', resource['name'])
            if vpc_id:
                hierarchy['regions'][region]['vpcs'][vpc_id]['subnets'][subnet_id]['subnet_resource'] = resource
        elif resource_type in VPC_LEVEL_RESOURCES:
            vpc_id = attrs.get('vpc_id', default_vpc_id)
            if vpc_id:
                hierarchy['regions'][region]['vpcs'][vpc_id]['vpc_level'].append(resource)
            else:
                hierarchy['regions'][region]['regional'].append(resource)
        elif resource_type in SUBNET_LEVEL_RESOURCES:
            subnet_id = attrs.get('subnet_id', '')
            if subnet_id and subnet_id in actual_subnets:
                subnet_resource = actual_subnets[subnet_id]
                subnet_vpc_id = subnet_resource['attributes'].get('vpc_id', default_vpc_id)
                if subnet_vpc_id:
                    hierarchy['regions'][region]['vpcs'][subnet_vpc_id]['subnets'][subnet_id]['instances'].append(resource)
            else:
                vpc_id = attrs.get('vpc_id', default_vpc_id)
                if vpc_id:
                    hierarchy['regions'][region]['vpcs'][vpc_id]['vpc_level'].append(resource)
                else:
                    hierarchy['regions'][region]['regional'].append(resource)
        else:
            vpc_id = attrs.get('vpc_id', default_vpc_id)
            if vpc_id and vpc_id in actual_vpcs:
                hierarchy['regions'][region]['vpcs'][vpc_id]['vpc_level'].append(resource)
            else:
                hierarchy['regions'][region]['regional'].append(resource)
    
    # Clean up empty containers
    cleaned_hierarchy = {'global': hierarchy['global'], 'regions': {}}
    for region, region_data in hierarchy['regions'].items():
        if region_data['regional'] or region_data['vpcs']:
            cleaned_hierarchy['regions'][region] = {
                'regional': region_data['regional'],
                'vpcs': {}
            }
            
            for vpc_id, vpc_data in region_data['vpcs'].items():
                has_content = (vpc_data.get('vpc_resource') or vpc_data['vpc_level'] or 
                             any(subnet_data['instances'] or subnet_data['subnet_level'] or subnet_data.get('subnet_resource') 
                                 for subnet_data in vpc_data['subnets'].values()))
                if has_content:
                    cleaned_hierarchy['regions'][region]['vpcs'][vpc_id] = {
                        'vpc_resource': vpc_data.get('vpc_resource'),
                        'vpc_level': vpc_data['vpc_level'],
                        'subnets': {}
                    }
                    
                    for subnet_id, subnet_data in vpc_data['subnets'].items():
                        if (subnet_data.get('subnet_resource') or subnet_data['instances'] or subnet_data['subnet_level']):
                            cleaned_hierarchy['regions'][region]['vpcs'][vpc_id]['subnets'][subnet_id] = subnet_data
    
    return cleaned_hierarchy


def create_resource_node(resource: Dict[str, Any], eip_associations: Dict[str, Dict[str, str]]):
    """Create a diagram node for the given resource."""
    resource_type = resource['type']
    label = get_resource_label(resource, eip_associations)
    
    if resource_type in CONTAINER_RESOURCES or resource_type in HIDDEN_RESOURCES:
        return None
    
    node_class = RESOURCE_MAPPING.get(resource_type, General)
    return node_class(label)


def get_vpc_label(vpc_resource: Dict[str, Any], vpc_id: str) -> str:
    """Get VPC label with CIDR information."""
    if vpc_resource:
        cidr = vpc_resource['attributes'].get('cidr_block', '')
        name = get_resource_label(vpc_resource, {})
        return f"VPC: {name} ({cidr})" if cidr else f"VPC: {name}"
    return f"VPC: {vpc_id}"


def get_subnet_label(subnet_resource: Dict[str, Any], subnet_id: str) -> str:
    """Get subnet label with CIDR and type information."""
    if subnet_resource:
        attrs = subnet_resource['attributes']
        cidr = attrs.get('cidr_block', '')
        map_public = attrs.get('map_public_ip_on_launch', False)
        subnet_type = "Public" if map_public else "Private"
        return f"{subnet_type} ({cidr})" if cidr else f"{subnet_type} Subnet"
    return f"Subnet: {subnet_id}"


def find_connections(resources: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """Identify connections between resources."""
    connections = []
    resource_by_id = {}
    igw_nodes = []
    nat_nodes = []
    
    for resource in resources:
        attrs = resource['attributes']
        resource_id = attrs.get('id', '')
        if resource_id:
            resource_by_id[resource_id] = resource
        
        if resource['type'] == 'aws_internet_gateway':
            igw_nodes.append(resource)
        elif resource['type'] == 'aws_nat_gateway':
            nat_nodes.append(resource)
    
    # IGW to NAT Gateway connections
    for igw in igw_nodes:
        for nat in nat_nodes:
            igw_vpc = igw['attributes'].get('vpc_id', '')
            nat_vpc = nat['attributes'].get('vpc_id', '')
            if igw_vpc == nat_vpc:
                connections.append((igw['name'], nat['name']))
    
    return connections


def infer_missing_infrastructure(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Infer missing AWS infrastructure components that should be present."""
    inferred_resources = []
    
    # For demonstration, add basic inferred infrastructure
    # In a real implementation, this would analyze existing resources
    # and infer missing components like default VPCs, route tables, etc.
    
    return inferred_resources


def print_resource_summary(resources: List[Dict[str, Any]]) -> None:
    """Print a summary of the resources found."""
    resource_counts = defaultdict(int)
    for resource in resources:
        resource_counts[resource['type']] += 1
    
    print(f"\nResource Summary:")
    print(f"Total resources: {len(resources)}")
    for resource_type, count in sorted(resource_counts.items()):
        print(f"  {resource_type}: {count}")


def create_diagram_connections(resource_nodes: Dict[str, Any], connections: List[Tuple[str, str]]) -> None:
    """Create visual connections between related resources."""
    for source_name, target_name in connections:
        if source_name in resource_nodes and target_name in resource_nodes:
            source_node = resource_nodes[source_name]
            target_node = resource_nodes[target_name]
            source_node >> target_node


def generate_png_diagram(resources: List[Dict[str, Any]], output_path: str) -> str:
    """Generate PNG diagram from resources."""
    eip_associations = process_eip_associations(resources)
    connections = find_connections(resources)
    hierarchy = organize_resources_by_hierarchy(resources)
    resource_nodes = {}
    
    # Create the main diagram
    diagram_filename = f"{output_path}/aws_architecture_diagram.png"
    
    with Diagram(
        name="AWS Architecture from Cloud Infrastructure", 
        filename=diagram_filename.replace('.png', ''),
        show=False,
        direction="TB",
        graph_attr={
            "splines": "ortho",
            "nodesep": "1.0",
            "ranksep": "1.0",
            "fontsize": "12"
        }
    ):
        # Global Services
        if hierarchy['global']:
            with Cluster("Global Services"):
                for resource in hierarchy['global']:
                    node = create_resource_node(resource, eip_associations)
                    if node:
                        resource_nodes[resource['name']] = node
        
        # Regional Services
        for region, region_data in hierarchy['regions'].items():
            if not region_data['regional'] and not region_data['vpcs']:
                continue
                
            with Cluster(f"Region: {region}"):
                # Regional level resources
                for resource in region_data['regional']:
                    node = create_resource_node(resource, eip_associations)
                    if node:
                        resource_nodes[resource['name']] = node
                
                # VPCs
                for vpc_id, vpc_data in region_data['vpcs'].items():
                    vpc_resource = vpc_data.get('vpc_resource')
                    vpc_label = get_vpc_label(vpc_resource, vpc_id)
                    
                    with Cluster(vpc_label):
                        # VPC level resources
                        for resource in vpc_data['vpc_level']:
                            node = create_resource_node(resource, eip_associations)
                            if node:
                                resource_nodes[resource['name']] = node
                        
                        # Subnets
                        for subnet_id, subnet_data in vpc_data['subnets'].items():
                            subnet_resource = subnet_data.get('subnet_resource')
                            if not subnet_resource and not subnet_data['instances'] and not subnet_data['subnet_level']:
                                continue
                                
                            subnet_label = get_subnet_label(subnet_resource, subnet_id)
                            
                            with Cluster(subnet_label):
                                # Subnet resources
                                for resource in subnet_data['subnet_level']:
                                    node = create_resource_node(resource, eip_associations)
                                    if node:
                                        resource_nodes[resource['name']] = node
                                
                                # Instance resources
                                for resource in subnet_data['instances']:
                                    node = create_resource_node(resource, eip_associations)
                                    if node:
                                        resource_nodes[resource['name']] = node
        
        # Create connections
        create_diagram_connections(resource_nodes, connections)
    
    return diagram_filename


async def call_external_mcp_tool(tool_name: str, **kwargs):
    """Call a tool from the external Epam-InfraDriftDetector MCP server."""
    try:
        # This is a placeholder for the actual MCP client call
        # In a real implementation, you would establish a connection to the external server
        # and call the tool with the provided parameters
        
        # For now, we'll simulate the call and return mock data
        # In production, replace this with actual MCP client implementation
        
        if tool_name == "import_deployed_resources":
            # Return mock success response
            return {"status": "success", "message": f"Resources imported to {kwargs.get('path_output', 'output')}"}
        
        elif tool_name == "read_imported_tfstates":
            # Return mock tfstate data
            return [
                {
                    "type": "aws_vpc",
                    "name": "main-vpc",
                    "attributes": {
                        "id": "vpc-12345678",
                        "cidr_block": "10.0.0.0/16",
                        "region": "us-east-1"
                    }
                },
                {
                    "type": "aws_subnet",
                    "name": "public-subnet",
                    "attributes": {
                        "id": "subnet-87654321",
                        "vpc_id": "vpc-12345678",
                        "cidr_block": "10.0.1.0/24",
                        "map_public_ip_on_launch": True,
                        "region": "us-east-1"
                    }
                }
            ]
        
        else:
            return {"error": f"Unknown tool: {tool_name}"}
            
    except Exception as e:
        return {"error": str(e)}


@mcp.tool(
    name="awscloud_to_diagram",
    description="Generate AWS architecture diagrams from deployed cloud infrastructure. Imports AWS resources using Terraformer and creates PNG diagrams showing the architecture."
)
async def awscloud_to_diagram(
    cloud: str = "aws",
    resources: str = "vpc,subnet,ec2_instance,sg,s3,rds,lambda",
    regions: str = "us-east-1",
    output_path: str = "aws_architecture",
    format_type: str = "png"
) -> str:
    """
    Generate AWS architecture diagram from deployed cloud infrastructure.
    
    Args:
        cloud: Cloud provider (currently supports 'aws')
        resources: Comma-separated list of AWS resources to import (e.g., 'vpc,subnet,ec2,s3,rds')
        regions: Comma-separated list of AWS regions to scan
        output_path: Path where the diagram PNG file will be saved
        format_type: Format of the output diagram (e.g., 'png', 'drawio', 'mermaid')
    Returns:
        JSON string with operation status and details
    """
    try:
        resource_nodes = {} # Store created resource nodes for connections
        temp_dir = tempfile.mkdtemp(prefix="aws_diagram_")
            
        # Step 1: Import deployed resources using external MCP tool
        import_result = await call_external_mcp_tool(
            "import_deployed_resources",
            cloud=cloud,
            resources=resources,
            regions=regions,
            path_output=temp_dir
        )
        
        if "error" in import_result:
            return json.dumps({
                "status": "error",
                "message": f"Failed to import resources: {import_result['error']}"
            })
            
        # Step 2: Read imported tfstate files using external MCP tool
        tfstate_data = await call_external_mcp_tool(
            "read_imported_tfstates",
            post_deployed_tfstates_path=temp_dir
        )



        """Generate the architecture diagram from the Terraform state."""
        # parse the tfstate files stored in the imported directory
  
        resources = extract_resources(tfstate_data)
        
        print(f"Extracted {len(resources)} resources from Terraform state")
        
        try:
            # Add inferred missing infrastructure components
            inferred_resources = infer_missing_infrastructure(resources)
            all_resources = resources + inferred_resources
            
            print(f"Total resources including inferred: {len(all_resources)}")
            
            # Process EIP associations first
            process_eip_associations(all_resources)
            
            # Find connections between resources
            find_connections(all_resources)
            
            hierarchy = organize_resources_by_hierarchy(all_resources)
            
            # Add debug output for troubleshooting
            if format_type == "drawio":
                print_hierarchy_debug(hierarchy)
            
            if format_type == "drawio":
                # Generate draw.io diagram
                generate_drawio_diagram(hierarchy)
            elif format_type == "mermaid":
                # Generate Mermaid diagram
                generate_mermaid_diagram(hierarchy)
            else:
                # Generate PNG diagram using diagrams library
                # Create the main diagram
                with Diagram(
                    name="AWS Architecture from Terraform State", 
                    filename=output_name,
                    show=False,
                    direction="TB",
                    graph_attr={
                        "splines": "ortho",
                        "nodesep": "1.0",
                        "ranksep": "1.0",
                        "fontsize": "12"
                    }
                ):
                    
                    # Global Services
                    if hierarchy['global']:
                        with Cluster("Global Services"):
                            for resource in hierarchy['global']:
                                node = create_resource_node(resource)
                                if node:
                                    resource_nodes[resource['name']] = node
                    
                    # Regional Services
                    for region, region_data in hierarchy['regions'].items():
                        if not region_data['regional'] and not region_data['vpcs']:
                            continue
                            
                        with Cluster(f"Region: {region}"):
                            
                            # Regional level resources (outside VPC)
                            for resource in region_data['regional']:
                                node = create_resource_node(resource)
                                if node:
                                    resource_nodes[resource['name']] = node
                            
                            # VPCs
                            for vpc_id, vpc_data in region_data['vpcs'].items():
                                vpc_resource = vpc_data.get('vpc_resource')
                                vpc_label = get_vpc_label(vpc_resource, vpc_id)
                                
                                with Cluster(vpc_label):
                                    
                                    # VPC level resources
                                    for resource in vpc_data['vpc_level']:
                                        node = create_resource_node(resource)
                                        if node:
                                            resource_nodes[resource['name']] = node
                                    
                                    # Subnets (simplified - no AZ grouping)
                                    for subnet_id, subnet_data in vpc_data['subnets'].items():
                                        subnet_resource = subnet_data.get('subnet_resource')
                                        if not subnet_resource and not subnet_data['instances'] and not subnet_data['subnet_level']:
                                            continue
                                            
                                        subnet_label = get_subnet_label(subnet_resource, subnet_id)
                                        
                                        with Cluster(subnet_label):
                                            
                                            # Subnet level resources
                                            for resource in subnet_data['subnet_level']:
                                                node = create_resource_node(resource)
                                                if node:
                                                    resource_nodes[resource['name']] = node
                                            
                                            # Instance level resources (simplified grouping)
                                            for resource in subnet_data['instances']:
                                                node = create_resource_node(resource)
                                                if node:
                                                    resource_nodes[resource['name']] = node
                    
                    # Create connections after all nodes are created
                    create_diagram_connections()
                
                print(f"Architecture diagram generated successfully: {output_name}.png")
        except Exception as e:
            print(f"Error generating diagram: {str(e)}")
            return json.dumps({
                "status": "error",
                "message": f"Failed to generate diagram: {str(e)}",
                "output_file": None
            })
    except Exception as e:
        print(f"Error in diagram generation process: {str(e)}")
        return json.dumps({
            "status": "error",
            "message": f"Diagram generation failed: total_resources: {str(len(resources))} {str(e)}",
            "output_file": None
        })

def print_hierarchy_debug(self, hierarchy: Dict[str, Any]):
    """Print hierarchy structure for debugging."""
    print("\n=== HIERARCHY DEBUG ===")
    
    if hierarchy['global']:
        print(f"Global Services: {len(hierarchy['global'])}")
        for resource in hierarchy['global']:
            print(f"  - {resource['type']}: {resource['name']}")
    
    for region, region_data in hierarchy['regions'].items():
        print(f"\nRegion: {region}")
        
        if region_data['regional']:
            print(f"  Regional Services: {len(region_data['regional'])}")
            for resource in region_data['regional']:
                print(f"    - {resource['type']}: {resource['name']}")
        
        for vpc_id, vpc_data in region_data['vpcs'].items():
            vpc_resource = vpc_data.get('vpc_resource')
            vpc_name = vpc_resource['name'] if vpc_resource else 'Unknown'
            print(f"  VPC: {vpc_id} ({vpc_name})")
            
            if vpc_data['vpc_level']:
                print(f"    VPC Level: {len(vpc_data['vpc_level'])}")
                for resource in vpc_data['vpc_level']:
                    print(f"      - {resource['type']}: {resource['name']}")
            
            for subnet_id, subnet_data in vpc_data['subnets'].items():
                subnet_resource = subnet_data.get('subnet_resource')
                subnet_name = subnet_resource['name'] if subnet_resource else 'Unknown'
                total_resources = len(subnet_data['subnet_level']) + len(subnet_data['instances'])
                print(f"    Subnet: {subnet_id} ({subnet_name}) - {total_resources} resources")
                
                for resource in subnet_data['subnet_level'] + subnet_data['instances']:
                    print(f"      - {resource['type']}: {resource['name']}")
    
    print("=== END HIERARCHY DEBUG ===\n")

def print_hierarchy_debug(self, hierarchy: Dict[str, Any]):
    """Print hierarchy structure for debugging."""
    print("\n=== HIERARCHY DEBUG ===")
    
    if hierarchy['global']:
        print(f"Global Services: {len(hierarchy['global'])}")
        for resource in hierarchy['global']:
            print(f"  - {resource['type']}: {resource['name']}")
    
    for region, region_data in hierarchy['regions'].items():
        print(f"\nRegion: {region}")
        
        if region_data['regional']:
            print(f"  Regional Services: {len(region_data['regional'])}")
            for resource in region_data['regional']:
                print(f"    - {resource['type']}: {resource['name']}")
        
        for vpc_id, vpc_data in region_data['vpcs'].items():
            vpc_resource = vpc_data.get('vpc_resource')
            vpc_name = vpc_resource['name'] if vpc_resource else 'Unknown'
            print(f"  VPC: {vpc_id} ({vpc_name})")
            
            if vpc_data['vpc_level']:
                print(f"    VPC Level: {len(vpc_data['vpc_level'])}")
                for resource in vpc_data['vpc_level']:
                    print(f"      - {resource['type']}: {resource['name']}")
            
            for subnet_id, subnet_data in vpc_data['subnets'].items():
                subnet_resource = subnet_data.get('subnet_resource')
                subnet_name = subnet_resource['name'] if subnet_resource else 'Unknown'
                total_resources = len(subnet_data['subnet_level']) + len(subnet_data['instances'])
                print(f"    Subnet: {subnet_id} ({subnet_name}) - {total_resources} resources")
                
                for resource in subnet_data['subnet_level'] + subnet_data['instances']:
                    print(f"      - {resource['type']}: {resource['name']}")
    
    print("=== END HIERARCHY DEBUG ===\n")
    
def create_diagram_connections(self):
    """Create visual connections between related resources."""
    for source_name, target_name in self.connections:
        if source_name in self.resource_nodes and target_name in self.resource_nodes:
            source_node = self.resource_nodes[source_name]
            target_node = self.resource_nodes[target_name]
            # Create edge with arrow
            source_node >> target_node
    
    # ==================== MERMAID EXPORT FUNCTIONALITY ====================
    
def get_mermaid_node_shape(self, resource_type: str) -> str:
    """Get Mermaid node shape for AWS resource types."""
    mermaid_shapes = {
        # Compute - rectangles with rounded corners
        'aws_instance': '{}',
        'aws_lambda_function': '{}',
        'aws_elastic_beanstalk_application': '{}',
        
        # Database - cylinders (represented as special rectangles)
        'aws_db_instance': '[({})]',
        'aws_rds_cluster': '[({})]',
        'aws_dynamodb_table': '[({})]',
        
        # Storage - folders/documents
        'aws_s3_bucket': '[{}]',
        'aws_ebs_volume': '[{}]',
        'aws_efs_file_system': '[{}]',
        'aws_glacier_vault': '[{}]',
        'aws_storagegateway_gateway': '[{}]',
        
        # Network - diamonds for gateways, hexagons for networking
        'aws_internet_gateway': '{{{}}}',
        'aws_nat_gateway': '{{{}}}',
        'aws_vpc_peering_connection': '{{{}}}',
        'aws_ec2_transit_gateway': '{{{}}}',
        'aws_dx_connection': '{{{}}}',
        'aws_lb': '{{{}}}',
        'aws_alb': '{{{}}}',
        'aws_elb': '{{{}}}',
        'aws_route_table': '{{{}}}',
        'aws_route': '{{{}}}',
        'aws_route_table_association': '{{{}}}',
        'aws_route53_zone': '{{{}}}',
        'aws_route53_record': '{{{}}}',
        
        # Container and Analytics - rectangles
        'aws_ecr_repository': '[{}]',
        
        # Integration - circles
        'aws_sns_topic': '(({}))',
        'aws_sqs_queue': '(({}))',
        
        # Security and IAM - shields (represented as special rectangles)
        'aws_iam_user': '[{}]',
        'aws_iam_role': '[{}]',
        'aws_iam_group': '[{}]',
        'aws_kms_key': '[{}]',
        'aws_security_group': '[{}]',
        'aws_network_acl': '[{}]',
        
        # Monitoring - rectangles
        'aws_cloudwatch_log_group': '[{}]',
        
        # Default - simple rectangle
        'default': '[{}]'
    }
    
    return mermaid_shapes.get(resource_type, mermaid_shapes['default'])
    
def create_mermaid_node(self, resource: Dict[str, Any], parent_prefix: str = "") -> str:
    """Create a Mermaid node for a resource."""
    node_id = f"{parent_prefix}R{self.mermaid_node_counter}"
    self.mermaid_node_counter += 1
    
    # Get clean label (remove newlines and special characters for Mermaid)
    label = self.get_resource_label(resource)
    # Clean the label for Mermaid compatibility
    label = label.replace('\n', ' ').replace('"', "'").replace('[', '(').replace(']', ')')
    label = label.replace('{', '(').replace('}', ')').replace('|', '-')
    
    # Truncate very long labels
    if len(label) > 50:
        label = label[:47] + "..."
    
    # Get shape template
    shape_template = self.get_mermaid_node_shape(resource['type'])
    
    # Format the node with escaped label
    node_definition = f"    {node_id}{shape_template.format(label)}"
    
    # Store for connection lookup
    self.drawio_resource_lookup[resource['name']] = node_id
    
    return node_definition
    
def generate_mermaid_layout(self, hierarchy: Dict[str, Any]) -> None:
    """Generate Mermaid diagram layout from hierarchy."""
    self.mermaid_content = []
    self.drawio_resource_lookup.clear()
    self.mermaid_node_counter = 1
    
    # Start with graph definition
    self.mermaid_content.append("graph TB")
    self.mermaid_content.append("    %% AWS Architecture from Terraform State")
    self.mermaid_content.append("")
    
    # Global Services
    if hierarchy['global']:
        self.mermaid_content.append("    %% Global Services")
        self.mermaid_content.append("    subgraph GlobalServices [\"🌐 Global Services\"]")
        
        for resource in hierarchy['global']:
            if resource['type'] not in self.hidden_resources:
                node_def = self.create_mermaid_node(resource, "G")
                self.mermaid_content.append(f"    {node_def}")
        
        self.mermaid_content.append("    end")
        self.mermaid_content.append("")
    
    # Regional Services
    for region, region_data in hierarchy['regions'].items():
        if not region_data['regional'] and not region_data['vpcs']:
            continue
        
        region_prefix = region.replace('-', '').replace('_', '').replace('.', '')
        region_label = region.replace('(', '').replace(')', '')  # Clean region name for Mermaid
        
        self.mermaid_content.append(f"    %% Region: {region}")
        self.mermaid_content.append(f"    subgraph Region{region_prefix} [\"🏢 Region {region_label}\"]")
        
        # Regional level resources
        if region_data['regional']:
            self.mermaid_content.append("        %% Regional Services")
            for resource in region_data['regional']:
                if resource['type'] not in self.hidden_resources:
                    node_def = self.create_mermaid_node(resource, f"{region_prefix}REG")
                    self.mermaid_content.append(f"    {node_def}")
            self.mermaid_content.append("")
        
        # VPCs
        for vpc_index, (vpc_id, vpc_data) in enumerate(region_data['vpcs'].items()):
            vpc_resource = vpc_data.get('vpc_resource')
            vpc_label_raw = self.get_vpc_label(vpc_resource, vpc_id)
            # Clean VPC label for Mermaid
            vpc_label = vpc_label_raw.replace('(', '').replace(')', '').replace(':', ' -')
            
            vpc_prefix = f"{region_prefix}VPC{vpc_index + 1}"
            
            self.mermaid_content.append(f"        %% {vpc_label}")
            self.mermaid_content.append(f"        subgraph {vpc_prefix} [\"🏠 {vpc_label}\"]")
            
            # VPC level resources
            if vpc_data['vpc_level']:
                self.mermaid_content.append("            %% VPC Level Resources")
                for resource in vpc_data['vpc_level']:
                    if resource['type'] not in self.hidden_resources:
                        node_def = self.create_mermaid_node(resource, vpc_prefix)
                        self.mermaid_content.append(f"        {node_def}")
                self.mermaid_content.append("")
            
            # Subnets
            for subnet_index, (subnet_id, subnet_data) in enumerate(vpc_data['subnets'].items()):
                subnet_resource = subnet_data.get('subnet_resource')
                if not subnet_resource and not subnet_data['instances'] and not subnet_data['subnet_level']:
                    continue
                
                subnet_label_raw = self.get_subnet_label(subnet_resource, subnet_id)
                # Clean subnet label for Mermaid
                subnet_label = subnet_label_raw.replace('(', '').replace(')', '').replace(':', ' -')
                subnet_prefix = f"{vpc_prefix}SUB{subnet_index + 1}"
                
                self.mermaid_content.append(f"            %% {subnet_label}")
                self.mermaid_content.append(f"            subgraph {subnet_prefix} [\"📡 {subnet_label}\"]")
                
                # Subnet resources
                all_subnet_resources = subnet_data['subnet_level'] + subnet_data['instances']
                for resource in all_subnet_resources:
                    if resource['type'] not in self.hidden_resources:
                        node_def = self.create_mermaid_node(resource, subnet_prefix)
                        self.mermaid_content.append(f"            {node_def}")
                
                self.mermaid_content.append("            end")
                self.mermaid_content.append("")
            
            self.mermaid_content.append("        end")
            self.mermaid_content.append("")
        
        self.mermaid_content.append("    end")
        self.mermaid_content.append("")
    
    # Add connections
    if self.connections:
        self.mermaid_content.append("    %% Connections")
        for source_name, target_name in self.connections:
            source_id = self.drawio_resource_lookup.get(source_name)
            target_id = self.drawio_resource_lookup.get(target_name)
            
            if source_id and target_id:
                self.mermaid_content.append(f"    {source_id} --> {target_id}")
        self.mermaid_content.append("")
    
    # Add styling
    self.mermaid_content.extend([
        "    %% Styling",
        "    classDef compute fill:#ff9999,stroke:#333,stroke-width:2px",
        "    classDef network fill:#99ccff,stroke:#333,stroke-width:2px", 
        "    classDef storage fill:#99ff99,stroke:#333,stroke-width:2px",
        "    classDef database fill:#ffcc99,stroke:#333,stroke-width:2px",
        "    classDef security fill:#ff99cc,stroke:#333,stroke-width:2px",
        ""
    ])
    
def export_to_mermaid(self, filename: str) -> None:
    """Export the diagram to Mermaid format."""
    mermaid_text = '\n'.join(self.mermaid_content)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(mermaid_text)
    
    print(f"Mermaid diagram exported to: {filename}")

def generate_mermaid_diagram(self, hierarchy: Dict[str, Any]):
    """Generate Mermaid diagram from hierarchy."""
    print("Generating Mermaid layout...")
    self.generate_mermaid_layout(hierarchy)
    
    mermaid_filename = f"{self.output_name}.mmd"
    self.export_to_mermaid(mermaid_filename)
    
    # Count different element types
    total_lines = len(self.mermaid_content)
    subgraphs = sum(1 for line in self.mermaid_content if 'subgraph' in line)
    nodes = sum(1 for line in self.mermaid_content if line.strip().startswith('R') or line.strip().startswith('G'))
    connections = sum(1 for line in self.mermaid_content if '-->' in line)
    
    print(f"\nMermaid file created successfully!")
    print(f"Diagram content: {total_lines} lines")
    print(f"  - Containers: {subgraphs}")
    print(f"  - Resources: {nodes}")
    print(f"  - Connections: {connections}")
    print(f"\nView options:")
    print(f"  - Online editor: https://mermaid.live/")
    print(f"  - GitHub/GitLab: Supports .mmd files natively")
    print(f"  - VS Code: Install 'Mermaid Preview' extension")
    print(f"  - Documentation: Embed directly in Markdown")
    
    # Create a simple HTML preview file
    html_filename = f"{self.output_name}_mermaid_preview.html"
    mermaid_text = '\n'.join(self.mermaid_content)
    self.create_mermaid_html_preview(html_filename, mermaid_text)
    
def create_mermaid_html_preview(self, filename: str, mermaid_content: str):
    """Create an HTML file to preview the Mermaid diagram."""
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Architecture - Mermaid Preview</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<style>
    body {{ 
        font-family: Arial, sans-serif; 
        margin: 20px; 
        background-color: #f5f5f5; 
    }}
    .container {{ 
        max-width: 100%; 
        margin: 0 auto; 
        background: white; 
        padding: 20px; 
        border-radius: 8px; 
        box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
    }}
    h1 {{ 
        color: #333; 
        text-align: center; 
    }}
    .mermaid {{ 
        text-align: center; 
        margin: 20px 0; 
    }}
    .info {{ 
        background: #e7f3ff; 
        border: 1px solid #b3d9ff; 
        border-radius: 4px; 
        padding: 15px; 
        margin: 20px 0; 
    }}
    .code {{ 
        background: #f8f9fa; 
        border: 1px solid #e9ecef; 
        border-radius: 4px; 
        padding: 15px; 
        margin: 20px 0; 
        font-family: 'Courier New', monospace; 
        font-size: 12px; 
        white-space: pre-wrap; 
        overflow-x: auto; 
    }}
</style>
</head>
<body>
<div class="container">
    <h1>AWS Architecture Diagram - Mermaid</h1>
    
    <div class="info">
        <strong>🎯 Interactive Diagram:</strong><br>
        • Click and drag to pan around<br>
        • Use mouse wheel to zoom in/out<br>
        • This diagram is generated from your Terraform state file
    </div>
    
    <div class="mermaid">
{mermaid_content}
    </div>
    
    <div class="info">
        <strong>📝 How to use this diagram:</strong><br>
        • <strong>Copy source:</strong> See the code below to embed in documentation<br>
        • <strong>Edit online:</strong> Copy code to <a href="https://mermaid.live/" target="_blank">mermaid.live</a><br>
        • <strong>GitHub/GitLab:</strong> Save as .mmd file for native support<br>
        • <strong>VS Code:</strong> Install 'Mermaid Preview' extension<br>
    </div>
    
    <h3>Mermaid Source Code:</h3>
    <div class="code">{mermaid_content.replace('<', '&lt;').replace('>', '&gt;')}</div>
</div>

<script>
    mermaid.initialize({{ 
        startOnLoad: true,
        theme: 'default',
        flowchart: {{
            useMaxWidth: true,
            htmlLabels: true
        }}
    }});
</script>
</body>
</html>"""
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML preview created: {filename}")
    print(f"Open in browser: file://{Path(filename).absolute()}")

# ==================== DRAW.IO EXPORT FUNCTIONALITY ====================
    
def get_drawio_shape_style(self, resource_type: str) -> str:
    """Get draw.io shape style for AWS resource types."""
    aws_shapes = {
        # Compute
        'aws_instance': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#F78E04;gradientDirection=north;fillColor=#D05C17;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.ec2;',
        'aws_lambda_function': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#F78E04;gradientDirection=north;fillColor=#D05C17;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.lambda;',
        
        # Database
        'aws_db_instance': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#4D27AA;gradientDirection=north;fillColor=#7AA116;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.rds;',
        'aws_dynamodb_table': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#4D27AA;gradientDirection=north;fillColor=#7AA116;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.dynamodb;',
        
        # Storage
        'aws_s3_bucket': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#60A337;gradientDirection=north;fillColor=#277116;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.s3;',
        'aws_ebs_volume': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#60A337;gradientDirection=north;fillColor=#277116;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.elastic_block_store;',
        
        # Network
        'aws_internet_gateway': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#945DF2;gradientDirection=north;fillColor=#5A30B5;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.internet_gateway;',
        'aws_nat_gateway': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#945DF2;gradientDirection=north;fillColor=#5A30B5;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.nat_gateway;',
        'aws_lb': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#945DF2;gradientDirection=north;fillColor=#5A30B5;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.application_load_balancer;',
        'aws_route_table': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#945DF2;gradientDirection=north;fillColor=#5A30B5;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.route_table;',
        
        # Security
        'aws_security_group': 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=#F54749;gradientDirection=north;fillColor=#C7131F;strokeColor=#ffffff;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.security_group;',
        
        # Default
        'default': 'rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;'
    }
    
    return aws_shapes.get(resource_type, aws_shapes['default'])
    
def get_next_id(self) -> str:
    """Get next unique ID for draw.io elements."""
    current_id = str(self.next_id)
    self.next_id += 1
    return current_id
    
def create_drawio_resource(self, resource: Dict[str, Any], x: int, y: int, parent_id: str = "1") -> str:
    """Create a draw.io XML element for a resource."""
    resource_id = self.get_next_id()
    label = self.get_resource_label(resource)
    style = self.get_drawio_shape_style(resource['type'])
    
    # Create element with unique key based on resource name and ID
    element_key = f"resource_{resource_id}_{resource['name']}"
    element = {
        'id': resource_id,
        'value': label,
        'style': style,
        'vertex': '1',
        'parent': parent_id,
        'x': str(x),
        'y': str(y),
        'width': '78',
        'height': '78'
    }
    
    # Store element only once with unique key
    self.drawio_elements[element_key] = element
    # Store in lookup for connections (separate from main elements)
    self.drawio_resource_lookup[resource['name']] = element
    return resource_id
    
def create_drawio_container(self, label: str, x: int, y: int, width: int, height: int, parent_id: str = "1") -> str:
    """Create a draw.io container (group/cluster)."""
    container_id = self.get_next_id()
    
    # Container style - lighter colors for better visibility
    container_style = 'rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;verticalAlign=top;fontStyle=1;fontSize=12;'
    
    element_key = f"container_{container_id}"
    element = {
        'id': container_id,
        'value': label,
        'style': container_style,
        'vertex': '1',
        'parent': parent_id,
        'x': str(x),
        'y': str(y),
        'width': str(width),
        'height': str(height)
    }
    
    # Store element only once
    self.drawio_elements[element_key] = element
    return container_id
    
def create_drawio_connection(self, source_name: str, target_name: str) -> str:
    """Create a draw.io connection between two resources."""
    # Look for the source and target elements in the lookup
    source_element = self.drawio_resource_lookup.get(source_name)
    target_element = self.drawio_resource_lookup.get(target_name)
    
    if not source_element or not target_element:
        print(f"Warning: Could not create connection from {source_name} to {target_name}")
        return ""
    
    connection_id = self.get_next_id()
    
    connection_style = 'edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#23445d;strokeWidth=2;endArrow=block;endFill=1;'
    
    element_key = f"connection_{connection_id}"
    element = {
        'id': connection_id,
        'value': '',
        'style': connection_style,
        'edge': '1',
        'parent': '1',
        'source': source_element['id'],
        'target': target_element['id']
    }
    
    # Store element only once
    self.drawio_elements[element_key] = element
    return connection_id
    
def generate_drawio_layout(self, hierarchy: Dict[str, Any]) -> None:
    """Generate draw.io layout from hierarchy - simplified to match PNG output."""
    current_y = 50
    current_x = 50
    
    # Clear existing elements to avoid duplicates
    self.drawio_elements.clear()
    self.drawio_resource_lookup.clear()
    self.next_id = 2  # Start from 2 since 0 and 1 are reserved
    
    print(f"Starting draw.io layout generation...")
    
    # Global Services
    if hierarchy['global']:
        print(f"Creating global services container with {len(hierarchy['global'])} services")
        global_container_id = self.create_drawio_container("Global Services", current_x, current_y, 400, 150, "1")
        res_x = current_x + 20
        res_y = current_y + 40
        
        for resource in hierarchy['global']:
            if resource['type'] not in self.hidden_resources:
                self.create_drawio_resource(resource, res_x, res_y, global_container_id)
                res_x += 100
        current_y += 200
    
    # Regional Services
    for region, region_data in hierarchy['regions'].items():
        if not region_data['regional'] and not region_data['vpcs']:
            continue
        
        print(f"Processing region: {region}")
        print(f"  Regional services: {len(region_data['regional'])}")
        print(f"  VPCs: {len(region_data['vpcs'])}")
        
        # Calculate region size based on actual content
        vpc_count = len(region_data['vpcs'])
        region_width = max(1000, vpc_count * 600 + 100)
        region_height = 600
        
        region_container_id = self.create_drawio_container(f"Region: {region}", current_x, current_y, region_width, region_height, "1")
        
        # Regional level resources (outside VPC)
        resource_x = current_x + 20
        resource_y = current_y + 40
        
        for resource in region_data['regional']:
            if resource['type'] not in self.hidden_resources:
                print(f"    Adding regional resource: {resource['type']} - {resource['name']}")
                self.create_drawio_resource(resource, resource_x, resource_y, region_container_id)
                resource_x += 100
        
        # VPCs - place them side by side within the region
        vpc_start_y = current_y + 120
        vpc_x = current_x + 20
        
        for vpc_index, (vpc_id, vpc_data) in enumerate(region_data['vpcs'].items()):
            vpc_resource = vpc_data.get('vpc_resource')
            vpc_label = self.get_vpc_label(vpc_resource, vpc_id)
            
            print(f"  Processing VPC: {vpc_id} ({vpc_label})")
            print(f"    VPC level resources: {len(vpc_data['vpc_level'])}")
            print(f"    Subnets: {len(vpc_data['subnets'])}")
            
            # Calculate VPC size based on subnets
            subnet_count = len(vpc_data['subnets'])
            vpc_level_resources = len(vpc_data['vpc_level'])
            
            # Width: accommodate subnets side by side
            vpc_width = max(500, subnet_count * 280 + 100)
            # Height: accommodate VPC resources at top and subnets below
            vpc_height = 400
            
            vpc_container_id = self.create_drawio_container(vpc_label, vpc_x, vpc_start_y, vpc_width, vpc_height, region_container_id)
            
            # VPC level resources - place horizontally at the top
            vpc_resource_x = vpc_x + 20
            vpc_resource_y = vpc_start_y + 40
            
            for resource in vpc_data['vpc_level']:
                if resource['type'] not in self.hidden_resources:
                    print(f"      Adding VPC resource: {resource['type']} - {resource['name']}")
                    self.create_drawio_resource(resource, vpc_resource_x, vpc_resource_y, vpc_container_id)
                    vpc_resource_x += 100
                    # Wrap to next row if needed
                    if vpc_resource_x > vpc_x + vpc_width - 100:
                        vpc_resource_x = vpc_x + 20
                        vpc_resource_y += 100
            
            # Subnets - place them horizontally below VPC resources
            subnet_start_y = vpc_start_y + 150  # Below VPC resources
            subnet_x = vpc_x + 20
            
            for subnet_index, (subnet_id, subnet_data) in enumerate(vpc_data['subnets'].items()):
                subnet_resource = subnet_data.get('subnet_resource')
                if not subnet_resource and not subnet_data['instances'] and not subnet_data['subnet_level']:
                    continue
                
                subnet_label = self.get_subnet_label(subnet_resource, subnet_id)
                
                print(f"    Processing subnet: {subnet_id} ({subnet_label})")
                print(f"      Subnet resources: {len(subnet_data['subnet_level'])}")
                print(f"      Instance resources: {len(subnet_data['instances'])}")
                
                # Calculate subnet size based on instances
                all_subnet_resources = subnet_data['subnet_level'] + subnet_data['instances']
                subnet_width = max(200, min(250, len(all_subnet_resources) * 90 + 40))
                subnet_height = max(180, ((len(all_subnet_resources) // 2) + 1) * 100 + 80)
                
                subnet_container_id = self.create_drawio_container(subnet_label, subnet_x, subnet_start_y, subnet_width, subnet_height, vpc_container_id)
                
                # Place resources within subnet
                instance_x = subnet_x + 20
                instance_y = subnet_start_y + 50
                
                for i, resource in enumerate(all_subnet_resources):
                    if resource['type'] not in self.hidden_resources:
                        print(f"        Adding subnet resource: {resource['type']} - {resource['name']}")
                        self.create_drawio_resource(resource, instance_x, instance_y, subnet_container_id)
                        
                        # Position next resource (2 per row)
                        if (i + 1) % 2 == 0:
                            instance_x = subnet_x + 20
                            instance_y += 90
                        else:
                            instance_x += 100
                
                # Move to next subnet position
                subnet_x += subnet_width + 20
            
            # Move to next VPC position (if multiple VPCs)
            vpc_x += vpc_width + 30
        
        current_y += region_height + 50
    
    print(f"Layout generation complete. Creating connections...")
    
    # Create connections after all elements are positioned
    for source_name, target_name in self.connections:
        print(f"  Creating connection: {source_name} -> {target_name}")
        self.create_drawio_connection(source_name, target_name)
    
def validate_drawio_elements(self) -> bool:
    """Validate draw.io elements for consistency."""
    issues = []
    ids_used = set()
    
    # Get all unique elements (no duplicates since we store each element only once)
    for element_name, element_data in self.drawio_elements.items():
        element_id = element_data.get('id')
        
        # Check for duplicate IDs (should not happen now)
        if element_id in ids_used:
            issues.append(f"Duplicate ID found: {element_id} in {element_name}")
        else:
            ids_used.add(element_id)
        
        # Check parent references
        parent_id = element_data.get('parent')
        if parent_id and parent_id not in ['0', '1']:
            parent_exists = any(e.get('id') == parent_id for e in self.drawio_elements.values())
            if not parent_exists:
                issues.append(f"Invalid parent reference: {parent_id} in {element_name}")
        
        # Check edge source/target references
        if 'edge' in element_data:
            source_id = element_data.get('source')
            target_id = element_data.get('target')
            
            if source_id:
                source_exists = any(e.get('id') == source_id for e in self.drawio_elements.values())
                if not source_exists:
                    issues.append(f"Invalid source reference: {source_id} in {element_name}")
            
            if target_id:
                target_exists = any(e.get('id') == target_id for e in self.drawio_elements.values())
                if not target_exists:
                    issues.append(f"Invalid target reference: {target_id} in {element_name}")
    
    if issues:
        print("Draw.io validation issues found:")
        for issue in issues:
            print(f"  - {issue}")
        return False
    else:
        print(f"Draw.io elements validation passed - {len(self.drawio_elements)} elements verified")
        return True
    
def export_to_drawio(self, filename: str) -> None:
    """Export the diagram to draw.io XML format."""
    # Create the root mxfile element
    mxfile = ET.Element('mxfile', {
        'host': 'app.diagrams.net',
        'modified': '2024-01-01T00:00:00.000Z',
        'agent': 'Terraform State Diagram Generator',
        'version': '22.0.0'
    })
    
    # Create diagram element
    diagram = ET.SubElement(mxfile, 'diagram', {
        'id': 'aws-architecture',
        'name': 'AWS Architecture'
    })
    
    # Create mxGraphModel
    graph_model = ET.SubElement(diagram, 'mxGraphModel', {
        'dx': '1422',
        'dy': '794',
        'grid': '1',
        'gridSize': '10',
        'guides': '1',
        'tooltips': '1',
        'connect': '1',
        'arrows': '1',
        'fold': '1',
        'page': '1',
        'pageScale': '1',
        'pageWidth': '1654',
        'pageHeight': '2336',
        'math': '0',
        'shadow': '0'
    })
    
    # Create root element
    root = ET.SubElement(graph_model, 'root')
    
    # Add default cells
    ET.SubElement(root, 'mxCell', {'id': '0'})
    ET.SubElement(root, 'mxCell', {'id': '1', 'parent': '0'})
    
    # Sort elements by ID to ensure proper order (containers first, then resources, then connections)
    sorted_elements = sorted(self.drawio_elements.items(), key=lambda x: int(x[1]['id']))
    
    # Add all elements in order
    for element_name, element_data in sorted_elements:
        cell_attrs = {
            'id': element_data['id'],
            'value': element_data.get('value', ''),
            'style': element_data.get('style', ''),
            'parent': element_data.get('parent', '1')
        }
        
        if 'vertex' in element_data:
            cell_attrs['vertex'] = element_data['vertex']
        
        if 'edge' in element_data:
            cell_attrs['edge'] = element_data['edge']
            if 'source' in element_data:
                cell_attrs['source'] = element_data['source']
            if 'target' in element_data:
                cell_attrs['target'] = element_data['target']
        
        cell = ET.SubElement(root, 'mxCell', cell_attrs)
        
        # Add geometry for elements
        if 'vertex' in element_data and all(k in element_data for k in ['x', 'y', 'width', 'height']):
            geom_attrs = {
                'x': element_data['x'],
                'y': element_data['y'],
                'width': element_data['width'],
                'height': element_data['height'],
                'as': 'geometry'
            }
            ET.SubElement(cell, 'mxGeometry', geom_attrs)
        elif 'edge' in element_data:
            geom_attrs = {'relative': '1', 'as': 'geometry'}
            ET.SubElement(cell, 'mxGeometry', geom_attrs)
    
    # Write to file with proper formatting
    tree = ET.ElementTree(mxfile)
    ET.indent(tree, space="  ")
    tree.write(filename, encoding='utf-8', xml_declaration=True)
    print(f"Draw.io diagram exported to: {filename}")

def generate_drawio_diagram(self, hierarchy: Dict[str, Any]):
    """Generate draw.io diagram from hierarchy."""
    print("Generating draw.io layout...")
    self.generate_drawio_layout(hierarchy)
    
    print("Validating draw.io elements...")
    is_valid = self.validate_drawio_elements()
    
    if is_valid:
        drawio_filename = f"{self.output_name}.drawio"
        self.export_to_drawio(drawio_filename)
        
        # Count different element types
        containers = sum(1 for k in self.drawio_elements.keys() if k.startswith('container_'))
        resources = sum(1 for k in self.drawio_elements.keys() if k.startswith('resource_'))
        connections = sum(1 for k in self.drawio_elements.keys() if k.startswith('connection_'))
        
        # Provide helpful information
        print(f"\nDraw.io file created successfully!")
        print(f"Elements generated: {len(self.drawio_elements)} total")
        print(f"  - Containers: {containers}")
        print(f"  - Resources: {resources}")
        print(f"  - Connections: {connections}")
        print(f"Open at: https://app.diagrams.net/")
        print(f"Or install desktop app: https://github.com/jgraph/drawio-desktop/releases")
    else:
        print("Draw.io export cancelled due to validation errors")




if __name__ == "__main__":
    import asyncio
    mcp.run()