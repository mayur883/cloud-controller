"""
Apache HDFS Integration and Distributed Storage Engine.
Supports both direct WebHDFS REST API connection to real Apache Hadoop clusters
and an in-process, high-fidelity distributed LAN HDFS cluster engine with
multi-DataNode topology, rack-aware replica placement, heartbeat tracking,
and automated replica failover.
"""

from typing import Dict, List, Optional, Any
from pathlib import Path
import json
import time
import os
import shutil
import requests

from cloud_controller.config import (
    HDFS_STORAGE_ROOT,
    DATANODE_CONFIGS,
    DEFAULT_REPLICATION_FACTOR,
    HDFS_MODE,
    WEBHDFS_URL,
    WEBHDFS_USER,
)


class HDFSError(Exception):
    pass


class BlockNotFoundError(HDFSError):
    pass


class NodeUnavailableError(HDFSError):
    pass


class DataNode:
    """
    Simulates an Apache HDFS DataNode on a laboratory LAN machine or rack.
    Stores raw block data on local disk and reports block metrics.
    """
    def __init__(self, node_id: str, rack: str, host: str, capacity_bytes: int, storage_dir: Path):
        self.node_id = node_id
        self.rack = rack
        self.host = host
        self.capacity_bytes = capacity_bytes
        self.storage_dir = storage_dir / node_id / "blocks"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.is_online = True
        self.last_heartbeat = time.time()

    def write_block_data(self, block_rel_path: str, data: bytes) -> int:
        if not self.is_online:
            raise NodeUnavailableError(f"DataNode {self.node_id} is offline")
        
        target = self.storage_dir / block_rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
        self.last_heartbeat = time.time()
        return len(data)

    def read_block_data(self, block_rel_path: str) -> bytes:
        if not self.is_online:
            raise NodeUnavailableError(f"DataNode {self.node_id} is offline")
        
        target = self.storage_dir / block_rel_path
        if not target.exists():
            raise BlockNotFoundError(f"Block {block_rel_path} not found on DataNode {self.node_id}")
        
        with open(target, "rb") as f:
            return f.read()

    def delete_block_data(self, block_rel_path: str) -> bool:
        if not self.is_online:
            raise NodeUnavailableError(f"DataNode {self.node_id} is offline")
        
        target = self.storage_dir / block_rel_path
        if target.exists():
            target.unlink()
            return True
        return False

    def get_used_space(self) -> int:
        total = 0
        if self.storage_dir.exists():
            for root, _, files in os.walk(self.storage_dir):
                for f in files:
                    total += os.path.getsize(os.path.join(root, f))
        return total

    def count_blocks(self) -> int:
        count = 0
        if self.storage_dir.exists():
            for root, _, files in os.walk(self.storage_dir):
                count += len(files)
        return count

    def to_dict(self) -> Dict[str, Any]:
        used = self.get_used_space()
        return {
            "node_id": self.node_id,
            "rack": self.rack,
            "host": self.host,
            "is_online": self.is_online,
            "capacity_bytes": self.capacity_bytes,
            "used_bytes": used,
            "free_bytes": max(0, self.capacity_bytes - used),
            "usage_pct": round((used / self.capacity_bytes) * 100, 2) if self.capacity_bytes > 0 else 0,
            "block_count": self.count_blocks(),
            "last_heartbeat": round(time.time() - self.last_heartbeat, 1),
        }


class DistributedLANHDFSEngine:
    """
    Fault-tolerant Apache HDFS cluster engine designed for Laboratory LANs.
    Coordinates multiple DataNodes with rack-awareness and replication policies.
    """
    def __init__(self, storage_root: Path = HDFS_STORAGE_ROOT):
        self.storage_root = storage_root
        self.datanodes: Dict[str, DataNode] = {}
        for cfg in DATANODE_CONFIGS:
            dn = DataNode(
                node_id=cfg["id"],
                rack=cfg["rack"],
                host=cfg["host"],
                capacity_bytes=cfg["capacity_bytes"],
                storage_dir=self.storage_root,
            )
            self.datanodes[cfg["id"]] = dn

    def select_nodes_for_replication(self, replication_factor: int) -> List[DataNode]:
        """
        Rack-aware DataNode selection algorithm:
        1. Place first replica on a node with the lowest storage utilization in Rack 1.
        2. Place second replica on a node in a different Rack (Rack 2) for fault-tolerance.
        3. Place subsequent replicas on remaining nodes.
        """
        online_nodes = [dn for dn in self.datanodes.values() if dn.is_online]
        if not online_nodes:
            raise HDFSError("All HDFS DataNodes are currently offline or unreachable.")
        
        target_count = min(replication_factor, len(online_nodes))
        
        # Sort nodes by used space ascending (least loaded first)
        sorted_nodes = sorted(online_nodes, key=lambda n: n.get_used_space())
        
        chosen = []
        racks_seen = set()
        
        # First pick cross-rack if possible
        for node in sorted_nodes:
            if node.rack not in racks_seen:
                chosen.append(node)
                racks_seen.add(node.rack)
            if len(chosen) >= target_count:
                break
                
        # If still need more replicas, pick from remaining nodes
        for node in sorted_nodes:
            if node not in chosen and len(chosen) < target_count:
                chosen.append(node)
                
        return chosen

    def write_block(
        self,
        block_rel_path: str,
        data: bytes,
        replication_factor: int = DEFAULT_REPLICATION_FACTOR,
    ) -> List[str]:
        """
        Distributes and writes block data across multiple DataNodes according to replication policy.
        Returns list of DataNode IDs where replicas were successfully placed.
        """
        target_nodes = self.select_nodes_for_replication(replication_factor)
        successful_nodes = []

        for node in target_nodes:
            try:
                node.write_block_data(block_rel_path, data)
                successful_nodes.append(node.node_id)
            except Exception as e:
                # Log and continue writing remaining replicas
                continue

        if not successful_nodes:
            raise HDFSError(f"Failed to write block {block_rel_path} to any DataNode.")

        return successful_nodes

    def read_block(self, block_rel_path: str, replica_nodes: Optional[List[str]] = None) -> bytes:
        """
        Reads block data from the first available healthy DataNode holding a replica.
        Automatically fails over to alternate replicas if a node is offline or corrupted.
        """
        nodes_to_try = []
        if replica_nodes:
            # Check specified replicas first
            for nid in replica_nodes:
                if nid in self.datanodes and self.datanodes[nid].is_online:
                    nodes_to_try.append(self.datanodes[nid])

        # Fallback to any online node that has the block
        for nid, dn in self.datanodes.items():
            if dn.is_online and dn not in nodes_to_try:
                nodes_to_try.append(dn)

        errors = []
        for dn in nodes_to_try:
            try:
                return dn.read_block_data(block_rel_path)
            except Exception as e:
                errors.append(f"{dn.node_id}: {str(e)}")
                continue

        raise BlockNotFoundError(f"Block {block_rel_path} could not be retrieved from any replica: {errors}")

    def delete_block(self, block_rel_path: str, replica_nodes: Optional[List[str]] = None) -> bool:
        """
        Deletes all replicas of the given block across all DataNodes.
        """
        nodes = [self.datanodes[nid] for nid in replica_nodes if nid in self.datanodes] if replica_nodes else self.datanodes.values()
        deleted_any = False
        for dn in nodes:
            try:
                if dn.delete_block_data(block_rel_path):
                    deleted_any = True
            except Exception:
                continue
        return deleted_any

    def toggle_node(self, node_id: str, online: bool) -> Dict[str, Any]:
        """Administrative hook to simulate node failure or recovery."""
        if node_id not in self.datanodes:
            raise HDFSError(f"Unknown DataNode {node_id}")
        self.datanodes[node_id].is_online = online
        self.datanodes[node_id].last_heartbeat = time.time()
        return self.datanodes[node_id].to_dict()

    def get_cluster_status(self) -> Dict[str, Any]:
        """Returns comprehensive HDFS cluster topology, health, and storage utilization."""
        nodes = [dn.to_dict() for dn in self.datanodes.values()]
        total_capacity = sum(n["capacity_bytes"] for n in nodes)
        total_used = sum(n["used_bytes"] for n in nodes)
        total_blocks = sum(n["block_count"] for n in nodes)
        online_count = sum(1 for n in nodes if n["is_online"])
        
        status = "HEALTHY"
        if online_count == 0:
            status = "CRITICAL_OFFLINE"
        elif online_count < len(nodes):
            status = "DEGRADED"

        return {
            "cluster_status": status,
            "mode": "Distributed LAN Cluster",
            "total_nodes": len(nodes),
            "online_nodes": online_count,
            "total_capacity_bytes": total_capacity,
            "total_used_bytes": total_used,
            "total_free_bytes": max(0, total_capacity - total_used),
            "overall_usage_pct": round((total_used / total_capacity) * 100, 2) if total_capacity > 0 else 0,
            "total_stored_block_replicas": total_blocks,
            "datanodes": nodes,
        }


class WebHDFSClient:
    """
    Standard WebHDFS REST API client for connecting to external Apache Hadoop clusters.
    Complies with Hadoop WebHDFS specification (RFC / Apache docs).
    """
    def __init__(self, base_url: str = WEBHDFS_URL, user: str = WEBHDFS_USER):
        self.base_url = base_url.rstrip("/")
        self.user = user

    def write_block(
        self,
        block_rel_path: str,
        data: bytes,
        replication_factor: int = DEFAULT_REPLICATION_FACTOR,
    ) -> List[str]:
        path = f"/lab_storage/{block_rel_path.lstrip('/')}"
        url = f"{self.base_url}{path}?op=CREATE&user.name={self.user}&overwrite=true&replication={replication_factor}"
        
        # Step 1: PUT to NameNode with redirect=false
        res = requests.put(url, allow_redirects=False, timeout=10)
        if res.status_code == 307:
            # Step 2: PUT payload to DataNode location header
            datanode_url = res.headers["Location"]
            res2 = requests.put(datanode_url, data=data, timeout=30)
            if res2.status_code not in (200, 201):
                raise HDFSError(f"WebHDFS DataNode write failed: {res2.status_code} {res2.text}")
        elif res.status_code in (200, 201):
            pass
        else:
            raise HDFSError(f"WebHDFS NameNode CREATE failed: {res.status_code} {res.text}")

        return ["webhdfs-external-cluster"]

    def read_block(self, block_rel_path: str, replica_nodes: Optional[List[str]] = None) -> bytes:
        path = f"/lab_storage/{block_rel_path.lstrip('/')}"
        url = f"{self.base_url}{path}?op=OPEN&user.name={self.user}"
        res = requests.get(url, allow_redirects=True, timeout=30)
        if res.status_code != 200:
            raise BlockNotFoundError(f"WebHDFS read failed: {res.status_code} {res.text}")
        return res.content

    def delete_block(self, block_rel_path: str, replica_nodes: Optional[List[str]] = None) -> bool:
        path = f"/lab_storage/{block_rel_path.lstrip('/')}"
        url = f"{self.base_url}{path}?op=DELETE&user.name={self.user}&recursive=true"
        res = requests.delete(url, timeout=10)
        return res.status_code == 200

    def get_cluster_status(self) -> Dict[str, Any]:
        return {
            "cluster_status": "CONNECTED",
            "mode": "External Apache WebHDFS",
            "endpoint": self.base_url,
            "user": self.user,
        }


# Global engine singleton
_engine_instance = None


def get_hdfs_engine():
    global _engine_instance
    if _engine_instance is None:
        if HDFS_MODE == "webhdfs":
            _engine_instance = WebHDFSClient()
        else:
            _engine_instance = DistributedLANHDFSEngine()
    return _engine_instance
