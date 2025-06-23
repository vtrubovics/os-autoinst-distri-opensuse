#!/usr/bin/env python3
"""
SCAP 1.2 DataStream Generator - Format Matcher
Produces output identical to the provided example structure
"""
import argparse
import os
import sys
import re
from datetime import datetime
from xml.etree import ElementTree as ET
import xml.dom.minidom

# SCAP 1.2 Namespaces
NS = {
    'ds': 'http://scap.nist.gov/schema/scap/source/1.2',
    'xlink': 'http://www.w3.org/1999/xlink',
    'cat': 'urn:oasis:names:tc:entity:xmlns:xml:catalog'
}

def register_namespaces():
    """Register XML namespaces for proper serialization"""
    for prefix, uri in NS.items():
        ET.register_namespace(prefix, uri)

def generate_component_id(prefix, filename):
    """Generate unique component ID matching example format"""
    clean_name = os.path.basename(filename)
    return f"scap_{prefix}_comp_{clean_name}"

def generate_ref_id(prefix, filename):
    """Generate unique reference ID matching example format"""
    clean_name = os.path.basename(filename)
    return f"scap_{prefix}_cref_{clean_name}"

def main():
    parser = argparse.ArgumentParser(
        description="Generate SCAP 1.2 DataStream matching specific format",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument('-x', '--xccdf', required=True, 
                        help="XCCDF 1.2 benchmark file")
    parser.add_argument('-o', '--oval', required=True, 
                        help="OVAL definition file")
    parser.add_argument('-out', '--output', required=True, 
                        help="Output DataStream XML file")
    parser.add_argument('--id-prefix', default="org.open-scap", 
                        help="Reverse DNS prefix for generated IDs")
    
    args = parser.parse_args()

    register_namespaces()

    # 1. Create root DataStream collection
    collection_id = f"scap_{args.id_prefix}_collection_from_xccdf_{os.path.basename(args.xccdf)}"
    root_attrib = {
        'id': collection_id,
        'schematron-version': '1.2'
    }
    root = ET.Element(f"{{{NS['ds']}}}data-stream-collection", **root_attrib)

    # 2. Create DataStream with required attributes
    stream_id = f"scap_{args.id_prefix}_datastream_from_xccdf_{os.path.basename(args.xccdf)}"
    stream_attrs = {
        'id': stream_id,
        'scap-version': '1.2',
        'use-case': 'OTHER'
    }
    data_stream = ET.SubElement(root, f"{{{NS['ds']}}}data-stream", **stream_attrs)

    # 3. Create component containers
    checklists = ET.SubElement(data_stream, f"{{{NS['ds']}}}checklists")
    checks = ET.SubElement(data_stream, f"{{{NS['ds']}}}checks")

    # 4. Process input files
    components = {}
    parsed_content = {}
    for file_path in [args.xccdf, args.oval]:
        try:
            tree = ET.parse(file_path)
            root_elem = tree.getroot()
            parsed_content[file_path] = root_elem
            components[file_path] = generate_component_id(args.id_prefix, file_path)
        except ET.ParseError as e:
            sys.exit(f"XML parse error in {file_path}: {e}")

    # Generate timestamp in the exact format used in the example
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # 5. Handle XCCDF checklist
    xccdf_ref_id = generate_ref_id(args.id_prefix, args.xccdf)
    xccdf_comp_id = components[args.xccdf]
    
    comp_ref = ET.SubElement(checklists, f"{{{NS['ds']}}}component-ref", {
        'id': xccdf_ref_id,
        f"{{{NS['xlink']}}}href": f"#{xccdf_comp_id}"
    })

    # Build XML catalog for XCCDF references
    catalog = ET.SubElement(comp_ref, f"{{{NS['cat']}}}catalog")
    ET.SubElement(catalog, f"{{{NS['cat']}}}uri", 
                 name="oval.xml", 
                 uri=f"#{generate_ref_id(args.id_prefix, args.oval)}")

    # 6. Handle OVAL checks
    oval_ref_id = generate_ref_id(args.id_prefix, args.oval)
    oval_comp_id = components[args.oval]
    ET.SubElement(checks, f"{{{NS['ds']}}}component-ref", {
        'id': oval_ref_id,
        f"{{{NS['xlink']}}}href": f"#{oval_comp_id}"
    })

    # 7. Add all components to collection
    for file_path, comp_id in components.items():
        comp = ET.Element(f"{{{NS['ds']}}}component", {
            'id': comp_id,
            'timestamp': timestamp
        })
        
        # Add the raw content without modifying namespaces
        comp.append(parsed_content[file_path])
        root.append(comp)

    # 8. Write final DataStream with proper formatting
    tree = ET.ElementTree(root)

    # Use minidom for pretty printing to match example format
    from xml.dom import minidom
    xml_str = ET.tostring(root, encoding='utf-8', method='xml')
    parsed = minidom.parseString(xml_str)
    pretty_xml = parsed.toprettyxml(indent="", encoding='utf-8')
    
    # Manual formatting adjustments to match example exactly
    formatted_xml = pretty_xml.decode('utf-8')
    formatted_xml = formatted_xml.replace("ns0:", "")
    formatted_xml = formatted_xml.replace('<?xml version="1.0" ?>', '<?xml version="1.0" encoding="utf-8"?>')

    # Clean up extra spaces
    formatted_xml = re.sub(r'^\s+\n', '', formatted_xml, flags=re.MULTILINE)
    formatted_xml = re.sub(r' +', ' ', formatted_xml, flags=re.MULTILINE)

    # Parse the XML string
    dom = xml.dom.minidom.parseString(formatted_xml)

    # Generate the pretty-printed XML string
    # '  ' specifies the indent string, and '\n' specifies the newline character
    pretty_xml = dom.toprettyxml(indent="  ")

    # The result often includes an XML declaration and extra newlines,
    # which can be cleaned up for a neater result.
    cleaned_xml = "\n".join([line for line in pretty_xml.split('\n') if line.strip()])
    formatted_xml = cleaned_xml
    
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(formatted_xml)

    print(f"Success: Created format-matched SCAP 1.2 DataStream at {args.output}")

if __name__ == '__main__':
    main()
