#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
# (c) Copyright 2025 - 2026 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

from typing import Dict, Any, Optional, List

import json
import uuid
from urllib.parse import quote
from datetime import datetime

from .container import uSwidContainer
from .format import uSwidFormatBase
from .component import uSwidComponent
from .entity import uSwidEntity, uSwidEntityRole
from .errors import NotSupportedError
from .hash import uSwidHashAlg
from .link import uSwidLink, uSwidLinkRel
from .purl import uSwidPurl
from uswid import container


def _convert_hash_alg_id(alg_id: uSwidHashAlg) -> str:
    return {
        uSwidHashAlg.SHA256: "SHA256",
        uSwidHashAlg.SHA384: "SHA384",
        uSwidHashAlg.SHA512: "SHA512",
    }.get(alg_id, "UNKNOWN")


def _normalize_spdx_namespace(namespace: Optional[str]) -> Optional[str]:
    if not namespace:
        return None
    namespace = namespace.rstrip("#/")
    if namespace.startswith("urn:uuid:"):
        namespace = namespace[len("urn:uuid:") :]
    return namespace


def _namespaced_tag_id(spdx_id: Optional[str], namespace: Optional[str]) -> Optional[str]:
    if not spdx_id:
        return None
    if spdx_id.startswith("SPDXRef-"):
        spdx_id = spdx_id[8:]
    if namespace:
        return f"{namespace}:{spdx_id}"
    return spdx_id


def _get_graph_nodes_by_type(data: Dict[str, Any], node_type: str) -> Optional[List[Dict[str, Any]]]:
    """Get all nodes of a given type from an SPDX 3.0 JSON-LD document."""
    if "@graph" not in data:
        return None
    graph = data["@graph"]
    if not isinstance(graph, list):
        return None
    nodes: List[Dict[str, Any]] = []
    for node in graph:
        if not isinstance(node, dict):
            continue
        curr_node_type = node.get("type")
        if curr_node_type:
            if isinstance(curr_node_type, str) and curr_node_type == node_type:
                nodes.append(node)
    return nodes


def _detect_spdx_json_version(data: Dict[str, Any]) -> str:
    """Best-effort detection of SPDX JSON serialization version."""
    # SPDX 3.0
    # Check CreationInfo node for specVersion field 
    creation_info_node = _get_graph_nodes_by_type(data, "CreationInfo")
    if creation_info_node:
        spec_version = creation_info_node[0].get("specVersion")
        if isinstance(spec_version, str) and "3.0" in spec_version:
            return "3.0"

    # Fallback - assume that the presence of "@graph" indicates SPDX 3.0, even if specVersion is missing or malformed.
    if "@graph" in data:
        return "3.0"

    # SPDX 2.3
    spdx_version = data.get("spdxVersion")
    if isinstance(spdx_version, str) and spdx_version == "SPDX-2.3":
        return "2.3"

    # Some SPDX 2.x JSON documents may omit spdxVersion in malformed cases.
    if "packages" in data or "SPDXID" in data:
        return "2.3"

    raise NotSupportedError("unrecognized SPDX JSON format")


def _spdx30_node_id(node: Dict[str, Any]) -> Optional[str]:
    return node.get("spdxId") or node.get("@id")


def _entity_to_spdx_anyuri(entity: uSwidEntity) -> Optional[str]:
    """Convert an entity identity into a stable xsd:anyURI string."""
    if not entity.name:
        return None
    stripped_name = entity.name.replace(" ", "_")
    encoded_name = quote(stripped_name, safe="")
    if not encoded_name:
        return None

    if entity.regid:
        # Use regid as the authority when available.
        return f"https://{entity.regid}/spdx/agent/{encoded_name}"

    # Fallback to a deterministic URN when no regid is available.
    stable_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"agent:{stripped_name}")
    return f"urn:uuid:{stable_uuid}:{stripped_name}"


class uSwidFormatSpdx(uSwidFormatBase):
    """SPDX file"""

    def _load_single_package(
        self,
        pkg: Dict[str, Any],
        data_root: Dict[str, Any],
        namespace: Optional[str],
    ) -> uSwidComponent:
        """Load a single package from SPDX 2.3 JSON data"""
        component = uSwidComponent()
        # tag_id
        component.tag_id = _namespaced_tag_id(pkg.get("SPDXID"), namespace)
        # externalRefs (purl)
        external_refs = pkg.get("externalRefs") or pkg.get("externalReferences") or []
        if isinstance(external_refs, list):
            for ref in external_refs:
                if not isinstance(ref, dict):
                    continue
                if ref.get("referenceType") != "purl":
                    continue
                locator = ref.get("referenceLocator")
                if locator:
                    component.purl = uSwidPurl(locator)
                    break
        # basic fields
        component.software_name = pkg.get("name")
        component.summary = pkg.get("summary")
        component.software_version = pkg.get("versionInfo")

        # licenseDeclared (best-effort extraction of SPDX IDs)
        spdx_license_ids = pkg.get("licenseDeclared")
        if spdx_license_ids:
            for spdx_license_id in spdx_license_ids.split(" AND "):
                component.add_link(
                    uSwidLink(
                        rel=uSwidLinkRel.LICENSE,
                        spdx_id=spdx_license_id,
                    )
                )

        # originator / supplier
        originator = pkg.get("originator")
        supplier = pkg.get("supplier")
        if supplier:
            if supplier.startswith("Organization: "):
                supplier = supplier[14:]
            component.add_entity(
                uSwidEntity(name=supplier, roles=[uSwidEntityRole.LICENSOR])
            )
        if originator:
            if originator.startswith("Organization: "):
                originator = originator[14:]
            component.add_entity(
                uSwidEntity(name=originator, roles=[uSwidEntityRole.SOFTWARE_CREATOR])
            )

        # creationInfo creators (tag creators)
        try:
            creators = data_root["creationInfo"]["creators"]
            for creator in creators:
                if creator.startswith("Organization: "):
                    component.add_entity(
                        uSwidEntity(
                            name=creator[14:], roles=[uSwidEntityRole.TAG_CREATOR]
                        )
                    )
                    break
                if creator.startswith("Person: "):
                    component.add_entity(
                        uSwidEntity(
                            name=creator[8:], roles=[uSwidEntityRole.TAG_CREATOR]
                        )
                    )
                    break
        except KeyError:
            pass

        return component

    def _load_single_node(
        self,
        node: Dict[str, Any],
        nodes_by_id: Dict[str, Dict[str, Any]],
    ) -> uSwidComponent:
        """Load a single SPDX 3.0 node from JSON data."""
        component = uSwidComponent()
        # tag_id
        component.tag_id = _namespaced_tag_id(node.get("spdxId"), None)

        # externalRefs (purl) - not implemented yet

        # basic fields
        component.software_name = node.get("name")

        component.summary = node.get("summary")

        component.software_version = node.get("software_packageVersion")

        # originator / supplier
        self._add_spdx30_agent_entities(
            component,
            node.get("suppliedBy"),
            nodes_by_id,
            uSwidEntityRole.LICENSOR,
        )
        self._add_spdx30_agent_entities(
            component,
            node.get("originatedBy"),
            nodes_by_id,
            uSwidEntityRole.SOFTWARE_CREATOR,
        )
        # creationInfo creators (tag creators)
        self._load_spdx30_creation_info(component, node, nodes_by_id)
        return component

    def _add_spdx30_agent_entities(
        self,
        component: uSwidComponent,
        entities: Any,
        nodes_by_id: Dict[str, Dict[str, Any]],
        role: uSwidEntityRole,
    ) -> None:
        if isinstance(entities, str):
            entity_refs = [entities]
        elif isinstance(entities, list):
            entity_refs = entities
        else:
            return
        for entity in entity_refs:
            if not isinstance(entity, str):
                continue
            node = nodes_by_id.get(entity)
            if node:
                name = node.get("name")
            else:
                # Keep unresolved references as-is for visibility rather than
                # silently dropping creators.
                name = entity
            if name and isinstance(name, str):
                component.add_entity(uSwidEntity(name=name, roles=[role]))

    def _load_spdx30_creation_info(
        self,
        component: uSwidComponent,
        node: Dict[str, Any],
        nodes_by_id: Dict[str, Dict[str, Any]],
    ) -> None:
        creation_info_ref = node.get("creationInfo")
        if not isinstance(creation_info_ref, str):
            return
        creation_info = nodes_by_id.get(creation_info_ref)
        if not creation_info:
            return
        self._add_spdx30_agent_entities(
            component,
            creation_info.get("createdBy"),
            nodes_by_id,
            uSwidEntityRole.TAG_CREATOR,
        )

    def __init__(self) -> None:
        """Initializes uSwidFormatSpdx"""
        uSwidFormatBase.__init__(self, "SPDX")
        self.version = None

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as e:
            raise NotSupportedError(f"invalid JSON file: {e}") from e

        self.version = _detect_spdx_json_version(data)
        if self.version == "2.3":
            return self._load_spdx23(data)
        if self.version == "3.0":
            return self._load_spdx30(data)

        raise NotSupportedError(f"unsupported SPDX JSON version {self.version}")

    def _load_spdx23(self, data: Dict[str, Any]) -> uSwidContainer:
        packages = data.get("packages")
        if not packages:
            # return empty container vs raising, depending on policy
            return uSwidContainer()

        # build components
        namespace = _normalize_spdx_namespace(data.get("documentNamespace"))
        components_by_spdxid = {}
        container = uSwidContainer()
        for pkg in packages:
            comp = self._load_single_package(pkg, data, namespace)
            pkg_spdxid = pkg.get("SPDXID")
            if pkg_spdxid:
                components_by_spdxid[pkg_spdxid] = comp
            container.append(comp)

        # relationships (dependencies)
        for rel in data.get("relationships", []):
            try:
                if rel.get("relationshipType") != "DEPENDS_ON":
                    continue
                src = rel["spdxElementId"]
                tgt = rel["relatedSpdxElement"]
                if src in components_by_spdxid and tgt in components_by_spdxid:
                    # add link from src -> tgt
                    csrc = components_by_spdxid[src]
                    ctgt = components_by_spdxid[tgt]
                    csrc.add_link(
                        uSwidLink(rel=uSwidLinkRel.COMPONENT, href=ctgt.tag_id)
                    )
            except KeyError:
                continue  # skip malformed relationship objects

        return container

    def _load_spdx30(self, data: Dict[str, Any]) -> uSwidContainer:
        graph = data.get("@graph")
        if not isinstance(graph, list):
            raise NotSupportedError("SPDX 3.0 JSON-LD document missing @graph list")

        # build nodes
        nodes_by_id: Dict[str, Dict[str, Any]] = {}
        for node in graph:
            if not isinstance(node, dict):
                continue
            node_id = _spdx30_node_id(node)
            if node_id:
                nodes_by_id[node_id] = node
        
        # handle software_Package class type
        container = uSwidContainer()
        components_by_spdxid: Dict[str, uSwidComponent] = {}
        for node in graph:
            if not isinstance(node, dict):
                continue
            node_type = node.get("type")
            if node_type == "software_Package":
                component = self._load_single_node(node, nodes_by_id)
                container.append(component)
                if component.tag_id:
                    components_by_spdxid[component.tag_id] = component
        # relationships (dependencies)
        self._load_spdx30_relationships(graph, components_by_spdxid)

        return container

    def _load_spdx30_relationship_depends_on(
        self,
        src: str,
        targets: List[str],
        components_by_spdxid: Dict[str, uSwidComponent],
    ) -> None:
        if src not in components_by_spdxid:
            return

        csrc = components_by_spdxid[src]
        for tgt in targets:
            if tgt not in components_by_spdxid:
                continue
            ctgt = components_by_spdxid[tgt]
            if not ctgt.tag_id:
                continue
            csrc.add_link(uSwidLink(rel=uSwidLinkRel.COMPONENT, href=ctgt.tag_id))

    def _load_spdx30_relationships(
        self,
        graph: List[Dict[str, Any]],
        components_by_spdxid: Dict[str, uSwidComponent],
    ) -> None:
        # Search for "Relationship" nodes
        for node in graph:
            if not isinstance(node, dict):
                continue
            if node.get("type") != "Relationship":
                continue

            relationship_type = node.get("relationshipType")
            if not isinstance(relationship_type, str):
                continue
            relationship_type = relationship_type.upper()

            # "from" field must have one element
            src = node.get("from")
            if not isinstance(src, str):
                continue

            # "to" field has one or more elements
            to_values = node.get("to")
            if isinstance(to_values, str):
                targets: List[str] = [to_values]
            elif isinstance(to_values, list):
                targets = [value for value in to_values if isinstance(value, str)]
            else:
                continue

            # Parse "dependsOn" relationship type
            if relationship_type == "DEPENDS_ON":
                self._load_spdx30_relationship_depends_on(
                    src, targets, components_by_spdxid
                )
    
    def save(self, container: uSwidContainer) -> bytes:
        if self.version == "2.3":
            return self._save_2_3(container)
        elif self.version == "3.0":
            return self._save_3_0(container)
        raise NotSupportedError(f"Unsupported SPDX version: {self.version}")

    def _save_2_3(self, container: uSwidContainer) -> bytes:
        # header
        root: Dict[str, Any] = {}
        root["SPDXID"] = "SPDXRef-DOCUMENT"
        root["spdxVersion"] = "SPDX-2.3"
        root["dataLicense"] = "CC0-1.0"
        root["documentNamespace"] = f"urn:uuid:{str(uuid.uuid4())}"
        # root["name"] = "uSWID SBOM")
        root["name"] = "NOASSERTION"

        # this has to be defined
        root["files"] = []

        # generator
        root["creationInfo"] = {
            "creators": ["Tool: uSWID"],
            "created": datetime.now().strftime("%FT%TZ"),
        }

        # tag creator
        creator: Optional[str] = None
        for component in container:
            for entity in component.entities:
                if uSwidEntityRole.TAG_CREATOR in entity.roles:
                    if entity.name:
                        creator = entity.name
        if creator:
            root["creationInfo"]["creators"].append(f"Organization: {creator}")

        # what packages are we describing
        document_describes: List[str] = []
        for component in container:
            document_describes.append(f"SPDXRef-{component.tag_id}")
        if document_describes:
            root["documentDescribes"] = document_describes

        # optional
        packages: List[Dict[str, Any]] = []
        for component in container:
            packages.append(self._save_2_3_component(component))
        if packages:
            root["packages"] = packages

        return json.dumps(root, indent=2, ensure_ascii=False).encode()

    def _save_3_0(self, container: uSwidContainer) -> bytes:
        root: Dict[str, Any] = {}
        root["@context"] = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

        # @graph nodes
        nodes: List[Dict[str, Any]] = []

        # creation info
        creation_info: Dict[str, Any] = {
            "type": "CreationInfo",
            "@id": "_:creationinfo",
            "createdBy": ["Tool: uSWID"],
            "specVersion": "3.0.1",
            "created": datetime.now().strftime("%FT%TZ"),
        }
        creator_names_by_uri: Dict[str, str] = {}
        agent_nodes: List[Dict[str, Any]] = []
        for component in container:
            for entity in component.entities:
                if uSwidEntityRole.TAG_CREATOR in entity.roles:
                    anyuri = _entity_to_spdx_anyuri(entity)
                    if anyuri and anyuri not in creation_info["createdBy"]:
                        creation_info["createdBy"].append(anyuri)
                        # simultaneously create agent nodes
                        # at minimum, the type, spdxId, and creationInfo properties are required
                        # there are "Person", "Organization", etc types, but we cannot determine programmatically
                        agent: Dict[str, Any] = {
                            "type": "Agent",
                            "spdxId": anyuri,
                            "name": entity.name,
                            "creationInfo": "_:creationinfo"
                        }
                        agent_nodes.append(agent)
                    if anyuri and entity.name:
                        creator_names_by_uri[entity.name] = anyuri

        nodes.append(creation_info)

        # Agent type
        for agent in agent_nodes:
            nodes.append(agent)

        # Package type
        for component in container:
            nodes.append(self._save_3_0_component(component, creator_names_by_uri))

        # Relationship type
        for component in container:
            for link in component.links:
                if link.rel in [uSwidLinkRel.COMPONENT]:
                    depends_on_relationship: Dict[str, Any] = {
                        "type": "Relationship",
                        "spdxId": str(uuid.uuid4()),
                        "creationInfo": "_:creationinfo",
                        "from": component.tag_id,
                        "relationshipType": "depends_on",
                        "to": [link.href],
                        "completeness": "complete"
                    }
                    nodes.append(depends_on_relationship)

        root["@graph"] = nodes
        return json.dumps(root, indent=4, ensure_ascii=False).encode()

    def _save_2_3_component(self, component: uSwidComponent) -> Dict[str, Any]:
        root: Dict[str, Any] = {}

        # attrs
        root["SPDXID"] = f"SPDXRef-{component.tag_id}"
        root["downloadLocation"] = "NOASSERTION"
        if component.product:
            root["name"] = component.product
        if component.summary:
            root["summary"] = component.summary
        if component.software_version:
            root["versionInfo"] = component.software_version
        # not sure where to store component.persistent_id or component.colloquial_version

        # checksums
        checksums: List[Dict[str, str]] = []
        if component.payloads:
            if component.payloads[0].name:
                root["packageFileName"] = component.payloads[0].name
            for ihash in component.payloads[0].hashes:
                checksum: Dict[str, str] = {}
                if ihash.value:
                    checksum["checksumValue"] = ihash.value
                if ihash.alg_id:
                    checksum["algorithm"] = _convert_hash_alg_id(ihash.alg_id)
                checksums.append(checksum)
        if checksums:
            root["checksums"] = checksums

        # supplier and authors
        originator: Optional[str] = None
        supplier: Optional[str] = None
        for entity in component.entities:
            if uSwidEntityRole.LICENSOR in entity.roles:
                if entity.name:
                    supplier = entity.name
            if uSwidEntityRole.SOFTWARE_CREATOR in entity.roles:
                if entity.name:
                    originator = entity.name
        if supplier:
            root["supplier"] = f"Organization: {supplier}"
        if originator:
            root["originator"] = f"Organization: {originator}"

        # annotations
        annotations = []
        for evidence in component.evidences:
            annotation = {"annotationType": "OTHER", "comment": "NOASSERTION"}
            if evidence.date:
                annotation["annotationDate"] = evidence.date.strftime("%FT%TZ")
            if evidence.device_id:
                annotation["annotator"] = f"Tool: {evidence.device_id}"
            annotations.append(annotation)
        if annotations:
            root["annotations"] = annotations

        # license
        license_spdx_ids = []
        for link in component.links:
            if link.rel != uSwidLinkRel.LICENSE:
                continue
            if link.spdx_id:
                license_spdx_ids.append(link.spdx_id)
        if license_spdx_ids:
            root["licenseDeclared"] = " AND ".join(license_spdx_ids)

        return root

    def _save_3_0_component(self, component: uSwidComponent, creator_names_by_uri: Dict[str, str]) -> Dict[str, Any]:
        package_spdx_id = component.tag_id
        if not package_spdx_id:
            if component.software_name:
                package_spdx_id = str(
                    uuid.uuid5(uuid.NAMESPACE_URL, f"package:{component.software_name}")
                )
            else:
                package_spdx_id = str(uuid.uuid4())

        # required fields
        root: Dict[str, Any] = {
            "type": "software_Package",
            "spdxId": package_spdx_id,
            "creationInfo": "_:creationinfo",
            "name":component.software_name,
        }

        # software version
        if component.software_version:
            root["software_packageVersion"] = component.software_version

        # download location
        root["software_downloadLocation"] = "NoneElement"

        # originator / supplier
        originator: Optional[str] = None
        supplier: Optional[str] = None
        for entity in component.entities:
            if uSwidEntityRole.LICENSOR in entity.roles:
                if entity.name:
                    supplier = creator_names_by_uri.get(entity.name, entity.name)
            if uSwidEntityRole.SOFTWARE_CREATOR in entity.roles:
                if entity.name:
                    originator = creator_names_by_uri.get(entity.name, entity.name)
        if originator:
            root["originatedBy"] = [originator]
        if supplier:
            root["suppliedBy"] = supplier

        if component.summary:
            root["summary"] = component.summary

        return root
